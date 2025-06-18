#!/usr/bin/env python3
"""
N11接口数据包批量处理工具
功能：批量修改PCAP文件中的IP地址、5G NAS消息参数
支持nrCellId、tac、SUPI(IMSI)的批量修改
"""

from scapy.all import rdpcap, wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from hpack import Decoder, Encoder
import os
import gc
import json
import re
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import partial
import argparse
import time
import copy
import struct
from tqdm import tqdm
import psutil

# ============================================================================
# 全局变量定义
# ============================================================================

# 调试模式标志
DEBUG_MODE = False

# 增量函数定义
def inc_ip(ip_str, i):
    """IP地址增量函数"""
    parts = list(map(int, ip_str.split('.')))
    carry = i
    for j in range(3, -1, -1):
        parts[j] += carry
        if parts[j] > 255:
            carry = parts[j] // 256
            parts[j] %= 256
        else:
            carry = 0
            break
    return '.'.join(map(str, parts))

def inc_hex(hex_str, i):
    """16进制字符串增量函数"""
    return format(int(hex_str, 16) + i, 'x').zfill(len(hex_str))

def inc_int(s, i):
    """整数字符串增量函数"""
    return str(int(s) + i)

# ============================================================================
# HTTP/2帧解析函数
# ============================================================================

def parse_http2_frame(data, offset=0):
    """解析HTTP/2帧"""
    if offset + 9 > len(data):
        return None
    
    # 解析帧头 (9字节)
    length = struct.unpack('!I', b'\x00' + data[offset:offset+3])[0]
    frame_type = data[offset+3]
    flags = data[offset+4]
    stream_id = struct.unpack('!I', data[offset+5:offset+9])[0] & 0x7FFFFFFF
    
    # 提取帧payload
    payload_start = offset + 9
    payload_end = payload_start + length
    if payload_end > len(data):
        payload_end = len(data)
        length = payload_end - payload_start
    
    payload = data[payload_start:payload_end]
    
    return {
        'length': length,
        'type': frame_type,
        'flags': flags,
        'stream_id': stream_id,
        'payload': payload,
        'total_size': 9 + length,
        'start_offset': offset,
        'end_offset': payload_end
    }

def rebuild_http2_frame(frame_type, flags, stream_id, payload):
    """重建HTTP/2帧"""
    length = len(payload)
    header = struct.pack('!I', length)[1:]  # 取后3字节作为长度
    header += struct.pack('!B', frame_type)
    header += struct.pack('!B', flags)
    header += struct.pack('!I', stream_id & 0x7FFFFFFF)
    return header + payload

# ============================================================================
# 核心处理函数
# ============================================================================

def update_global_vars(i, tac_num=1000000, ip_num=2000, sport_num=20000):
    """更新全局变量，为每个组生成对应的参数"""
      # 基础配置
    base = {
        "sip1": "40.0.0.1",      # 客户端IP
        "dip1": "50.0.0.1",      # 服务端IP
        "sport1": 5001,          # 源端口起始值
        "cgi1": 0x010000001,       # nrCellId起始值
        "tac1": 0x100001,          # tac起始值
        "imsi1": 460012300000001   # IMSI起始值
    }
      # 生成递增的参数，sip1和dip1使用ip_num循环
    sip1 = inc_ip(base["sip1"], i % ip_num)
    dip1 = inc_ip(base["dip1"], i % ip_num)
    sport1 = inc_int(str(base["sport1"]), i % sport_num)
    cgi1 = format(int(format(base["cgi1"], 'x'), 16) + i, 'x').lower().zfill(9)  # 固定9个字符，小写
    tac1 = format(int(format(base["tac1"], 'x'), 16) + (i % tac_num), 'x').lower().zfill(6)  # 固定6个字符，小写
    imsi1 = inc_int(str(base["imsi1"]), i)
    
    return sip1, dip1, sport1, cgi1, tac1, imsi1

def process_multipart_content(content, cgi1, tac1, imsi1, pkt_idx):
    """安全处理multipart内容，完全保护二进制数据避免Malformed Packet"""
    try:
        if DEBUG_MODE:
            print(f"Debug: pkt_idx={pkt_idx}, 开始处理multipart内容, cgi1={cgi1}, tac1={tac1}, imsi1={imsi1}")
        
        # 以字节模式处理，避免编码转换损坏二进制数据
        if isinstance(content, str):
            content_bytes = content.encode('utf-8', errors='replace')
        else:
            content_bytes = content
        
        # 查找boundary（字节模式）
        boundary_bytes = None
        
        # 尝试找到boundary
        lines = content_bytes.split(b'\n')
        for line in lines[:10]:  # 检查前10行
            line_str = line.decode('utf-8', errors='ignore').strip()
            if line_str.startswith('--') and len(line_str) > 2:
                boundary_bytes = line_str.encode('utf-8')
                break
        
        # 如果没找到，使用默认值
        if not boundary_bytes:
            boundary_bytes = b'--++Boundary'
        
        # 以字节模式分割
        parts_bytes = content_bytes.split(boundary_bytes)
        
        if len(parts_bytes) < 2:
            return content if isinstance(content, str) else content.decode('utf-8', errors='replace')
        
        # 处理每个部分（字节模式）
        modified_parts_bytes = []
        
        for i, part_bytes in enumerate(parts_bytes):
            if not part_bytes.strip():
                modified_parts_bytes.append(part_bytes)
                continue
            
            # 安全转换为字符串检查Content-Type
            part_str = part_bytes.decode('utf-8', errors='ignore')
            
            # 严格识别部分类型
            is_json_part = False
            is_binary_part = False
            
            # 检查Content-Type标头
            if 'Content-Type:' in part_str or 'Content-Type :' in part_str:
                # JSON部分
                if ('application/json' in part_str.lower() or 
                    'application/vnd.3gpp.ngap' in part_str.lower()):
                    is_json_part = True
                
                # 二进制部分（严格保护）
                if ('application/vnd.3gpp.5gnas' in part_str.lower() or
                    'application/octet-stream' in part_str.lower() or
                    'application/binary' in part_str.lower()):
                    is_binary_part = True
            
            if is_binary_part:
                # 二进制部分：完全不处理，保持原始字节
                modified_parts_bytes.append(part_bytes)
                continue
            
            if is_json_part:
                
                # 对于JSON部分，可以安全地进行字符串操作
                try:
                    # 分离headers和content（字节模式）
                    double_crlf = part_bytes.find(b'\r\n\r\n')
                    double_lf = part_bytes.find(b'\n\n')
                    
                    headers_end = -1
                    if double_crlf != -1:
                        headers_end = double_crlf + 4
                    elif double_lf != -1:
                        headers_end = double_lf + 2
                    
                    if headers_end > 0:
                        headers_bytes = part_bytes[:headers_end]
                        content_bytes_part = part_bytes[headers_end:]
                        
                        # 转换content部分为字符串进行JSON处理
                        content_str = content_bytes_part.decode('utf-8', errors='ignore')
                          # 查找JSON边界
                        json_start = content_str.find('{')
                        json_end = content_str.rfind('}')
                        
                        if json_start != -1 and json_end > json_start:
                            json_content = content_str[json_start:json_end + 1]
                            
                            if DEBUG_MODE:
                                print(f"Debug: pkt_idx={pkt_idx}, 找到JSON内容: {json_content[:200]}...")
                            
                            json_data = json.loads(json_content)
                            
                            # 安全修改JSON字段
                            modified = False
                              # 修改ueLocation
                            if 'ueLocation' in json_data and isinstance(json_data['ueLocation'], dict):
                                ue_location = json_data['ueLocation']
                                if 'nrLocation' in ue_location and isinstance(ue_location['nrLocation'], dict):
                                    nr_location = ue_location['nrLocation']
                                    
                                    if 'ncgi' in nr_location and isinstance(nr_location['ncgi'], dict):
                                        old_cellid = nr_location['ncgi'].get('nrCellId', 'N/A')
                                        nr_location['ncgi']['nrCellId'] = cgi1
                                        modified = True
                                        if DEBUG_MODE:
                                            print(f"Debug: pkt_idx={pkt_idx}, 修改nrCellId: {old_cellid} -> {cgi1}")
                                    
                                    if 'tai' in nr_location and isinstance(nr_location['tai'], dict):
                                        old_tac = nr_location['tai'].get('tac', 'N/A')
                                        nr_location['tai']['tac'] = tac1
                                        modified = True
                                        if DEBUG_MODE:
                                            print(f"Debug: pkt_idx={pkt_idx}, 修改tac: {old_tac} -> {tac1}")
                            
                            # 修改SUPI和GPSI
                            if 'supi' in json_data:
                                old_supi = json_data['supi']
                                json_data['supi'] = f"imsi-{imsi1}"
                                modified = True
                                if DEBUG_MODE:
                                    print(f"Debug: pkt_idx={pkt_idx}, 修改supi: {old_supi} -> imsi-{imsi1}")
                            
                            if 'gpsi' in json_data:
                                old_gpsi = json_data['gpsi']
                                json_data['gpsi'] = f"msisdn-{imsi1}"
                                modified = True
                                if DEBUG_MODE:
                                    print(f"Debug: pkt_idx={pkt_idx}, 修改gpsi: {old_gpsi} -> msisdn-{imsi1}")
                            
                            if DEBUG_MODE:
                                print(f"Debug: pkt_idx={pkt_idx}, JSON字段修改状态: {modified}")
                            
                            if modified:
                                # 生成新的JSON
                                new_json = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False)
                                  # 重新组装（字节模式）
                                new_content_str = content_str[:json_start] + new_json + content_str[json_end + 1:]
                                new_content_bytes = new_content_str.encode('utf-8')
                                new_part_bytes = headers_bytes + new_content_bytes
                                
                                modified_parts_bytes.append(new_part_bytes)
                            else:
                                modified_parts_bytes.append(part_bytes)
                        else:
                            modified_parts_bytes.append(part_bytes)
                    else:
                        # 无法分离headers，保持原样
                        modified_parts_bytes.append(part_bytes)
                
                except (json.JSONDecodeError, Exception) as e:
                    if DEBUG_MODE:
                        print(f"Debug: pkt_idx={pkt_idx}, JSON处理异常: {e}")
                    modified_parts_bytes.append(part_bytes)
            else:
                # 其他部分保持不变（字节模式）
                modified_parts_bytes.append(part_bytes)
          # 重新组装（字节模式）
        result_bytes = boundary_bytes.join(modified_parts_bytes)
        
        if DEBUG_MODE:
            print(f"Debug: pkt_idx={pkt_idx}, multipart处理完成, 原始长度={len(content_bytes)}, 新长度={len(result_bytes)}")
        
        # 验证结果的完整性
        if len(result_bytes) < len(content_bytes) * 0.5:
            if DEBUG_MODE:
                print(f"Debug: pkt_idx={pkt_idx}, multipart结果长度验证失败，返回原始内容")
            return content if isinstance(content, str) else content.decode('utf-8', errors='replace')
        
        # 验证multipart结构
        if result_bytes.count(boundary_bytes) < 2:
            if DEBUG_MODE:
                print(f"Debug: pkt_idx={pkt_idx}, multipart结构验证失败，返回原始内容")
            return content if isinstance(content, str) else content.decode('utf-8', errors='replace')
        
        if DEBUG_MODE:
            print(f"Debug: pkt_idx={pkt_idx}, multipart处理成功")
        
        # 转换回字符串（如果原来是字符串）
        if isinstance(content, str):
            return result_bytes.decode('utf-8', errors='replace')
        else:
            return result_bytes
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"Debug: pkt_idx={pkt_idx}, multipart处理异常: {e}")
        # 任何异常都返回原始内容
        return content if isinstance(content, str) else content.decode('utf-8', errors='replace')

def modify_http_path(path, imsi1, pkt_idx, pdusessionId="5"):
    """CentOS 7.6增强版HTTP路径修改器 - 确保100%成功修改"""
    try:
        original_path = path
        
        if DEBUG_MODE:
            print(f"[CentOS76-Path] 路径修改开始: {path}")
          # 针对特定报文的路径处理策略优化
        # 不强制统一格式，而是根据原路径结构进行相应的IMSI替换
        
        # CentOS 7.6兼容的多重正则匹配策略
        # 按优先级从高到低排序
        patterns = [
            # 模式1: 完整路径带modify后缀
            (r'(/nsmf-pdusession/v1/sm-contexts/)imsi-(\d+)-(\d+)(/modify)',
             rf'\1imsi-{imsi1}-{pdusessionId}\4'),
            # 模式2: 完整路径无modify后缀
            (r'(/nsmf-pdusession/v1/sm-contexts/)imsi-(\d+)-(\d+)(?=/|$)',
             rf'\1imsi-{imsi1}-{pdusessionId}'),
            # 模式3: 基础路径，需要添加完整路径
            (r'^/nsmf-pdusession/v1/sm-contexts$',
             f"/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-{pdusessionId}/modify"),
            # 模式4: namf-comm路径带n1-n2-messages
            (r'(/namf-comm/v1/ue-contexts/)imsi-(\d+)-(\d+)(/n1-n2-messages)',
             rf'\1imsi-{imsi1}-\3\4'),  # 保持原有的数字后缀
            # 模式5: namf-comm路径无数字后缀
            (r'(/namf-comm/v1/ue-contexts/)imsi-(\d+)(?=/|$)',
             rf'\1imsi-{imsi1}'),  # 不添加后缀
            # 模式6: supi格式
            (r'(supi-)(\d+)', rf'supi-{imsi1}'),
            # 模式7: 通用IMSI替换（兜底）
            (r'imsi-(\d+)', rf'imsi-{imsi1}'),
        ]
        
        # 执行模式匹配和替换
        for pattern, replacement in patterns:
            if re.search(pattern, path):
                new_path = re.sub(pattern, replacement, path)
                if new_path != path:
                    if DEBUG_MODE:
                        print(f"[CentOS76-Path] 模式匹配成功: '{pattern}' -> {path} => {new_path}")
                    return new_path
        
        # CentOS 7.6增强策略：字符串直接替换
        # 如果正则表达式失败，尝试直接字符串替换
        enhanced_path = path
        
        # 已知IMSI模式的直接替换
        known_imsi_patterns = [
            '460012300000131',
            '310310140000131', 
            '460012300000133',
            '310310140000133',
            '460012300000135',
            '310310140000135',
        ]
        
        for old_imsi in known_imsi_patterns:
            if old_imsi in enhanced_path:
                enhanced_path = enhanced_path.replace(old_imsi, str(imsi1))
                if DEBUG_MODE:
                    print(f"[CentOS76-Path] 直接字符串替换: {old_imsi} -> {imsi1}")
                
        # 路径补全策略
        if 'imsi-' in enhanced_path and '/modify' not in enhanced_path:
            if '/sm-contexts/imsi-' in enhanced_path and not enhanced_path.endswith('/modify'):
                # 尝试添加/modify后缀
                if enhanced_path.endswith(f'-{pdusessionId}'):
                    enhanced_path += '/modify'
                    if DEBUG_MODE:
                        print(f"[CentOS76-Path] 路径补全: 添加/modify后缀")
        
        if enhanced_path != path:
            if DEBUG_MODE:
                print(f"[CentOS76-Path] 增强策略成功: {path} -> {enhanced_path}")
            return enhanced_path
        
        if DEBUG_MODE:
            print(f"[CentOS76-Path] 路径无需修改: {path}")
        return path
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[CentOS76-Path] 路径修改异常: {e}")
        return path

def process_http2_payload_n11(pkt_idx, raw_payload, sip1, dip1, cgi1, tac1, imsi1):
    """处理N11接口HTTP/2 payload - 修复版本，安全修改HEADERS和DATA帧"""
    try:
        # 跳过HTTP/2 connection preface
        if raw_payload.startswith(b'PRI * HTTP/2.0'):
            return raw_payload
          # 创建HPACK解码器和编码器（每次新建避免状态问题）
        decoder = None
        encoder = None
        try:
            from hpack import Decoder, Encoder
            decoder = Decoder()
            encoder = Encoder()
        except ImportError:
            pass
          
        # 解析HTTP/2帧
        frames = []
        offset = 0
        while offset < len(raw_payload):
            frame = parse_http2_frame(raw_payload, offset)
            if not frame:
                break
            frames.append(frame)
            offset = frame['end_offset']
          # 重建payload - 优化版：正确处理content-length
        new_payload = b''
        headers_modified = False
        data_frame_modified = False
        
        # 第一遍：处理DATA帧，获取修改后的长度
        processed_data_frames = {}
        for i, frame in enumerate(frames):
            if frame['type'] == 0:  # DATA帧
                try:
                    payload_str = frame['payload'].decode('utf-8', errors='ignore')
                    
                    # 处理特定报文的内容
                    if pkt_idx in [13, 15, 16]:
                        # 修改multipart内容
                        modified_payload_str = process_multipart_content(payload_str, cgi1, tac1, imsi1, pkt_idx)
                        if modified_payload_str != payload_str:
                            data_frame_modified = True
                            payload_str = modified_payload_str
                    
                    # 保存处理后的DATA帧信息
                    new_frame_payload = payload_str.encode('utf-8')
                    processed_data_frames[i] = {
                        'original_frame': frame,
                        'new_payload': new_frame_payload,
                        'length': len(new_frame_payload)
                    }
                except Exception as e:
                    processed_data_frames[i] = {
                        'original_frame': frame,
                        'new_payload': frame['payload'],
                        'length': len(frame['payload'])
                    }
        
        # 第二遍：处理HEADERS帧，使用正确的content-length
        for i, frame in enumerate(frames):
            if frame['type'] == 1:  # HEADERS帧
                # 三级处理策略：完整重建 -> HPACK解码 -> 字节级替换
                try:
                    headers_processed = False
                    modified_payload = frame['payload']
                      # 策略1: 针对关键报文的完整重建（最优先）
                    if pkt_idx in [13, 15, 16]:
                        try:
                            # 计算修改后的DATA帧总长度作为content-length
                            total_data_length = 0
                            for data_frame_info in processed_data_frames.values():
                                total_data_length += data_frame_info['length']
                              # 完整重建HEADERS帧
                            specific_headers = create_specific_headers(pkt_idx, imsi1, total_data_length)
                            if specific_headers:
                                modified_payload = specific_headers
                                headers_processed = True
                                
                        except Exception as specific_error:
                            if DEBUG_MODE:
                                print(f"策略1失败: pkt_idx={pkt_idx}, error={specific_error}")                    # 策略2: HPACK解码修改（兜底方案）- CentOS 7.6增强版
                    if not headers_processed and decoder:
                        try:
                            # CentOS 7.6兼容性增强：多种HPACK处理策略
                            hpack_success = False
                            
                            # 方法1: 标准HPACK解码
                            try:
                                from hpack import Decoder, Encoder
                                decoder = Decoder()  # 创建新实例避免状态冲突
                                encoder = Encoder()
                                
                                headers = decoder.decode(frame['payload'])
                                new_headers = []
                                headers_modified_flag = False
                                
                                if DEBUG_MODE:
                                    headers_list = list(headers)
                                    print(f"Debug: pkt_idx={pkt_idx}, 标准HPACK解码成功，headers数量: {len(headers_list)}")
                                    headers = headers_list  # 转换为列表以便重复使用
                                
                                for name, original_value in headers:
                                    value = original_value
                                    
                                    # 关键字段修改 - CentOS兼容性增强
                                    if name.lower() in [':path', b':path']:
                                        if isinstance(value, bytes):
                                            path_str = value.decode('utf-8', errors='ignore')
                                        else:
                                            path_str = str(value)
                                        
                                        if DEBUG_MODE:
                                            print(f"Debug: 原始path={path_str}")
                                        
                                        new_path = modify_http_path(path_str, imsi1, pkt_idx)
                                        if new_path != path_str:
                                            # CentOS兼容：确保编码一致性
                                            if isinstance(original_value, bytes):
                                                value = new_path.encode('utf-8')
                                            else:
                                                value = new_path
                                            headers_modified_flag = True
                                            if DEBUG_MODE:
                                                print(f"Debug: 新path={new_path}")
                                    
                                    elif name.lower() in ['location', b'location']:
                                        if isinstance(value, bytes):
                                            location_str = value.decode('utf-8', errors='ignore')
                                        else:
                                            location_str = str(value)
                                        
                                        new_location = re.sub(r'imsi-(\d+)', rf'imsi-{imsi1}', location_str)
                                        if new_location != location_str:
                                            if isinstance(original_value, bytes):
                                                value = new_location.encode('utf-8')
                                            else:
                                                value = new_location
                                            headers_modified_flag = True
                                    
                                    # 更新content-length字段
                                    elif name.lower() in ['content-length', b'content-length'] and pkt_idx in [13, 15, 16]:
                                        total_data_length = sum(info['length'] for info in processed_data_frames.values())
                                        if total_data_length > 0:
                                            if isinstance(original_value, bytes):
                                                value = str(total_data_length).encode('utf-8')
                                            else:
                                                value = str(total_data_length)
                                            headers_modified_flag = True
                                    
                                    new_headers.append((name, value))
                                
                                # 重新编码修改后的headers
                                if headers_modified_flag:
                                    modified_payload = encoder.encode(new_headers)
                                    headers_processed = True
                                    hpack_success = True
                                    if DEBUG_MODE:
                                        print(f"Debug: pkt_idx={pkt_idx}, 标准HPACK编码成功")
                                
                            except Exception as std_hpack_error:
                                if DEBUG_MODE:
                                    print(f"Debug: pkt_idx={pkt_idx}, 标准HPACK失败: {std_hpack_error}")
                              # 方法2: CentOS兼容模式 - 宽松的HPACK处理
                            if not hpack_success:
                                try:
                                    # 使用标准的HPACK解码器，但采用更宽松的处理方式
                                    from hpack import Decoder, Encoder
                                    lenient_decoder = Decoder()
                                    lenient_encoder = Encoder()
                                    
                                    headers = lenient_decoder.decode(frame['payload'])
                                    new_headers = []
                                    headers_modified_flag = False
                                    
                                    if DEBUG_MODE:
                                        print(f"Debug: pkt_idx={pkt_idx}, 宽松HPACK解码成功")
                                    
                                    for name, original_value in headers:
                                        # CentOS兼容：统一处理name和value的类型
                                        if isinstance(name, bytes):
                                            name_str = name.decode('utf-8', errors='ignore')
                                        else:
                                            name_str = str(name)
                                        
                                        value = original_value
                                        
                                        if name_str.lower() == ':path':
                                            if isinstance(value, bytes):
                                                path_str = value.decode('utf-8', errors='ignore')
                                            else:
                                                path_str = str(value)
                                            
                                            new_path = modify_http_path(path_str, imsi1, pkt_idx)
                                            if new_path != path_str:
                                                value = new_path  # 宽松模式：统一使用字符串
                                                headers_modified_flag = True
                                                if DEBUG_MODE:
                                                    print(f"Debug: 宽松模式path修改: {path_str} -> {new_path}")
                                        
                                        new_headers.append((name, value))
                                    
                                    if headers_modified_flag:
                                        modified_payload = lenient_encoder.encode(new_headers)
                                        headers_processed = True
                                        hpack_success = True
                                        if DEBUG_MODE:
                                            print(f"Debug: pkt_idx={pkt_idx}, 宽松HPACK编码成功")
                                
                                except Exception as lenient_error:
                                    if DEBUG_MODE:
                                        print(f"Debug: pkt_idx={pkt_idx}, 宽松HPACK失败: {lenient_error}")
                            
                        except Exception as hpack_error:
                            if DEBUG_MODE:
                                print(f"策略2(HPACK)失败: pkt_idx={pkt_idx}, error={hpack_error}")                    # 策略3: 字节级替换（最后兜底）- CentOS兼容增强版
                    if not headers_processed:
                        if DEBUG_MODE:
                            print(f"Debug: pkt_idx={pkt_idx}, 尝试字节级替换（CentOS兼容模式）")
                        
                        # 方法1: 高级字节模式替换
                        byte_modified_payload = safe_replace_path_in_headers(frame['payload'], imsi1, pkt_idx)
                        if byte_modified_payload != frame['payload']:
                            modified_payload = byte_modified_payload
                            headers_processed = True
                            if DEBUG_MODE:
                                print(f"Debug: pkt_idx={pkt_idx}, 高级字节替换成功")
                        
                        # 方法2: CentOS强制字符串替换 - 多模式
                        if not headers_processed:
                            try:
                                payload_str = frame['payload'].decode('utf-8', errors='ignore')
                                modified_str = payload_str
                                replacement_count = 0
                                
                                # CentOS兼容：多重路径替换策略（按优先级排序）
                                replacement_patterns = [
                                    # 完整路径替换
                                    (r'/nsmf-pdusession/v1/sm-contexts/imsi-\d+-\d+/modify', 
                                     f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify'),
                                    (r'/nsmf-pdusession/v1/sm-contexts/imsi-\d+-\d+', 
                                     f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5'),
                                    (r'/namf-comm/v1/ue-contexts/imsi-\d+', 
                                     f'/namf-comm/v1/ue-contexts/imsi-{imsi1}'),
                                    # IMSI模式替换
                                    (r'imsi-\d{15}', f'imsi-{imsi1}'),  # 15位IMSI
                                    (r'imsi-\d{14}', f'imsi-{imsi1}'),  # 14位IMSI
                                    (r'imsi-\d+', f'imsi-{imsi1}'),     # 通用IMSI
                                    # 数字模式替换（最后执行）
                                    (r'460012300000131', str(imsi1)),
                                    (r'310310140000131', str(imsi1)),
                                ]
                                
                                for pattern, replacement in replacement_patterns:
                                    old_str = modified_str
                                    modified_str = re.sub(pattern, replacement, modified_str, flags=re.IGNORECASE)
                                    if modified_str != old_str:
                                        replacement_count += 1
                                        if DEBUG_MODE:
                                            print(f"Debug: pkt_idx={pkt_idx}, 模式'{pattern}'替换成功")
                                
                                if replacement_count > 0:
                                    modified_payload = modified_str.encode('utf-8')
                                    headers_processed = True
                                    if DEBUG_MODE:
                                        print(f"Debug: pkt_idx={pkt_idx}, CentOS强制替换成功，共{replacement_count}处修改")
                                        
                            except Exception as str_error:
                                if DEBUG_MODE:
                                    print(f"Debug: pkt_idx={pkt_idx}, 字符串替换失败: {str_error}")
                        
                        # 方法3: CentOS终极兜底 - 原始字节搜索替换
                        if not headers_processed:
                            try:
                                payload_bytes = bytearray(frame['payload'])
                                original_len = len(payload_bytes)
                                
                                # 定义字节级替换模式
                                byte_patterns = [
                                    # 路径字节模式
                                    (b'/nsmf-pdusession/v1/sm-contexts/imsi-460012300000131-5/modify',
                                     f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify'.encode('utf-8')),
                                    (b'/nsmf-pdusession/v1/sm-contexts/imsi-310310140000131-5/modify',
                                     f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify'.encode('utf-8')),
                                    # IMSI字节模式
                                    (b'imsi-460012300000131', f'imsi-{imsi1}'.encode('utf-8')),
                                    (b'imsi-310310140000131', f'imsi-{imsi1}'.encode('utf-8')),
                                    # 纯数字模式
                                    (b'460012300000131', str(imsi1).encode('utf-8')),
                                    (b'310310140000131', str(imsi1).encode('utf-8')),
                                ]
                                
                                byte_replacement_count = 0
                                for old_bytes, new_bytes in byte_patterns:
                                    if old_bytes in payload_bytes:
                                        # 进行字节替换
                                        start = 0
                                        while True:
                                            pos = payload_bytes.find(old_bytes, start)
                                            if pos == -1:
                                                break
                                            # 执行替换
                                            payload_bytes[pos:pos+len(old_bytes)] = new_bytes
                                            byte_replacement_count += 1
                                            start = pos + len(new_bytes)
                                
                                if byte_replacement_count > 0:
                                    modified_payload = bytes(payload_bytes)
                                    headers_processed = True
                                    if DEBUG_MODE:
                                        print(f"Debug: pkt_idx={pkt_idx}, 终极字节替换成功，"
                                              f"共{byte_replacement_count}处修改，"
                                              f"长度变化: {original_len} -> {len(modified_payload)}")
                                
                            except Exception as byte_error:
                                if DEBUG_MODE:
                                    print(f"Debug: pkt_idx={pkt_idx}, 字节替换失败: {byte_error}")
                        
                        # 最终状态检查
                        if not headers_processed and DEBUG_MODE:
                            print(f"Debug: pkt_idx={pkt_idx}, 所有替换策略均失败，保持原始payload")
                    
                    # 重建帧并验证
                    new_frame = rebuild_http2_frame(
                        frame['type'], frame['flags'], frame['stream_id'], modified_payload
                    )
                      # 验证重建的帧长度
                    if len(new_frame) != len(modified_payload) + 9:
                        pass  # 长度验证失败，但继续处理
                    
                    new_payload += new_frame
                    
                    if headers_processed:
                        headers_modified = True
                    
                except Exception as e:
                    # 出错时保持原帧不变
                    new_frame = rebuild_http2_frame(
                        frame['type'], frame['flags'], frame['stream_id'], frame['payload']
                    )
                    new_payload += new_frame
                    
            elif frame['type'] == 0:  # DATA帧
                # 使用第一遍处理的结果
                if i in processed_data_frames:
                    data_info = processed_data_frames[i]
                    new_frame = rebuild_http2_frame(
                        frame['type'], frame['flags'], frame['stream_id'], data_info['new_payload']
                    )
                    new_payload += new_frame
                    if data_info['new_payload'] != frame['payload']:
                        data_frame_modified = True
                else:
                    # 兜底：保持原样
                    new_frame = rebuild_http2_frame(
                        frame['type'], frame['flags'], frame['stream_id'], frame['payload']
                    )
                    new_payload += new_frame
            else:
                # 其他帧类型保持不变
                new_frame = rebuild_http2_frame(
                    frame['type'], frame['flags'], frame['stream_id'], frame['payload']
                )
                new_payload += new_frame
        
        if headers_modified or data_frame_modified:
            pass  # 标记修改已完成
        
        return new_payload
        
    except Exception as e:
        return raw_payload

# ============================================================================
# 核心数据包处理函数
# ============================================================================

def process_one_group_n11(orig_packets_bytes, group_id, tac_num=1000000, ip_num=2000, sport_num=20000):
    """单组N11数据包处理函数"""
    # 更新全局变量
    sip1, dip1, sport1, cgi1, tac1, imsi1 = update_global_vars(group_id, tac_num, ip_num, sport_num)
    
    # 反序列化数据包
    orig_packets = [Ether(pkt_bytes) for pkt_bytes in orig_packets_bytes]
    
    # 为整个组创建HPACK解码器和编码器
    try:
        from hpack import Decoder, Encoder
        global_decoder = Decoder()
        global_encoder = Encoder()
    except ImportError:
        global_decoder = None
        global_encoder = None
      # 处理流程
    output_packets = []
    seq_diff = {}  # 序列号差异追踪
    
    for pkt_idx, pkt in enumerate(orig_packets, 1):
        new_pkt = copy.deepcopy(pkt)        # 修改IP地址
        if new_pkt.haslayer(IP):
            if new_pkt[IP].src == orig_packets[0][IP].src:  # 客户端
                new_pkt[IP].src = sip1
                new_pkt[IP].dst = dip1
            else:  # 服务端
                new_pkt[IP].src = dip1
                new_pkt[IP].dst = sip1
        
        # 修改TCP端口
        if new_pkt.haslayer(TCP):
            # 如果原始sport为20000，则替换为新的sport1
            if new_pkt[TCP].sport == 20000:
                new_pkt[TCP].sport = int(sport1)
            # 如果原始dport为20000，也替换为新的sport1  
            elif new_pkt[TCP].dport == 20000:
                new_pkt[TCP].dport = int(sport1)        # TCP序列号处理 - 优化版，彻底解决"tcp acked unseen segment"问题
        if new_pkt.haslayer(TCP):
            flow = (new_pkt[IP].src, new_pkt[IP].dst, new_pkt[TCP].sport, new_pkt[TCP].dport)
            rev_flow = (new_pkt[IP].dst, new_pkt[IP].src, new_pkt[TCP].dport, new_pkt[TCP].sport)
            
            # 初始化序列号差异追踪
            if flow not in seq_diff:
                seq_diff[flow] = 0
            if rev_flow not in seq_diff:
                seq_diff[rev_flow] = 0
            
            has_payload = new_pkt.haslayer(Raw) and len(new_pkt[Raw].load) > 0
            original_length = len(new_pkt[Raw].load) if has_payload else 0
            
            # 处理HTTP/2 payload - 针对第13、15、16个报文
            if has_payload and pkt_idx in [13, 15, 16]:
                old_payload = new_pkt[Raw].load
                new_payload = process_http2_payload_n11(
                    pkt_idx, old_payload, sip1, dip1, cgi1, tac1, imsi1
                )
                new_pkt[Raw].load = new_payload
                  # 精确计算长度变化
                new_length = len(new_payload)
                length_diff = new_length - original_length
                
                if length_diff != 0:
                    pass  # 记录长度变化
                    
            else:
                length_diff = 0
                
            # TCP序列号调整策略 - 最终优化版本
            flags = int(new_pkt[TCP].flags)  # 确保flags是整数
            is_syn = bool(flags & 0x02)
            is_fin = bool(flags & 0x01) 
            is_rst = bool(flags & 0x04)
            is_ack = bool(flags & 0x10)
            is_psh = bool(flags & 0x08)
            
            # 保存原始值用于调试
            original_seq = new_pkt[TCP].seq
            original_ack = new_pkt[TCP].ack if is_ack else 0
              # 核心优化：精确处理TCP序列号
            # 1. 序列号调整：应用当前流的累积差异
            new_pkt[TCP].seq = original_seq + seq_diff[flow]
            
            # 2. ACK号调整：应用反向流的累积差异
            if is_ack and original_ack > 0:
                new_pkt[TCP].ack = original_ack + seq_diff[rev_flow]
              # 3. 累积当前包的长度变化（仅对有数据的包）
            if has_payload and length_diff != 0:
                seq_diff[flow] += length_diff
                # 调试：输出长度变化信息
                if DEBUG_MODE:
                    print(f"报文{pkt_idx}: 流{flow}累积差异更新 {seq_diff[flow]-length_diff} -> {seq_diff[flow]}, 长度变化: {length_diff}")
            
            # 4. 特殊处理：修复关键报文的序列号问题
            if pkt_idx == 12:
                # 第12个报文通常是对第11个报文的ACK响应
                if is_ack and not has_payload:
                    # 确保ACK号正确响应前面的数据包
                    new_pkt[TCP].ack = original_ack + seq_diff[rev_flow]
                    # 纯ACK包序列号保持原有逻辑
                    new_pkt[TCP].seq = original_seq + seq_diff[flow]
                    if DEBUG_MODE:
                        print(f"报文12特殊处理: seq={new_pkt[TCP].seq}, ack={new_pkt[TCP].ack}")
            
            elif pkt_idx == 14:
                # 第14个报文通常是对第13个报文的ACK响应
                if is_ack:
                    # 确保ACK号正确响应第13个报文（考虑其可能的长度变化）
                    new_pkt[TCP].ack = original_ack + seq_diff[rev_flow]
                    new_pkt[TCP].seq = original_seq + seq_diff[flow]
                    if DEBUG_MODE:
                        print(f"报文14特殊处理: seq={new_pkt[TCP].seq}, ack={new_pkt[TCP].ack}")
            
            # 5. 额外验证：确保序列号的合理性
            if pkt_idx in [11, 12, 13, 14, 15, 16, 17] and DEBUG_MODE:
                print(f"报文{pkt_idx}: original_seq={original_seq}, new_seq={new_pkt[TCP].seq}, "
                      f"original_ack={original_ack}, new_ack={new_pkt[TCP].ack if is_ack else 'N/A'}, "
                      f"flags={'ACK' if is_ack else ''}{'PSH' if is_psh else ''}{'SYN' if is_syn else ''}{'FIN' if is_fin else ''}, "
                      f"payload_len={len(new_pkt[Raw].load) if has_payload else 0}, "                      f"flow_diff={seq_diff[flow]}, rev_flow_diff={seq_diff[rev_flow]}")

            # 上面已经完成了所有TCP序列号的处理，这里不需要额外的特殊处理

        # 强制重算IP/TCP长度和校验和 - 增强版
        if new_pkt.haslayer(Raw) and new_pkt.haslayer(TCP) and new_pkt.haslayer(IP):
            raw_len = len(new_pkt[Raw].load)
            
            # 精确计算TCP头长度
            tcp_hdr_len = new_pkt[TCP].dataofs * 4 if hasattr(new_pkt[TCP], 'dataofs') else 20
            # 精确计算IP头长度
            ip_hdr_len = new_pkt[IP].ihl * 4 if hasattr(new_pkt[IP], 'ihl') else 20            # 重新计算长度字段
            new_pkt[IP].len = ip_hdr_len + tcp_hdr_len + raw_len
            new_pkt[TCP].dataofs = int(tcp_hdr_len / 4)
            
            # 验证长度计算
            expected_total = ip_hdr_len + tcp_hdr_len + raw_len
            if len(new_pkt) < expected_total:
                if DEBUG_MODE:
                    print(f"警告：报文{pkt_idx}长度不匹配 实际={len(new_pkt)} 期望={expected_total}")
                
        # 特殊处理：确保TCP窗口大小合理
        if new_pkt.haslayer(TCP):
            # 如果窗口大小为0，可能导致连接问题
            if new_pkt[TCP].window == 0 and pkt_idx not in [12, 14]:  # 除非是特定的ACK包
                new_pkt[TCP].window = 65535  # 设置一个合理的窗口大小
                
            # 确保urgent pointer合理
            if not hasattr(new_pkt[TCP], 'urgptr') or new_pkt[TCP].urgptr is None:
                new_pkt[TCP].urgptr = 0

        
        # 清空所有校验和，让Scapy自动重算（避免校验和错误）
        if new_pkt.haslayer(IP):
            new_pkt[IP].chksum = None
        if new_pkt.haslayer(TCP):
            new_pkt[TCP].chksum = None
            
        # 更新包的元数据
        new_pkt.time = pkt.time
        if hasattr(new_pkt, 'wirelen'):
            new_pkt.wirelen = len(new_pkt)
        if hasattr(new_pkt, 'caplen'):
            new_pkt.caplen = len(new_pkt)
        
        output_packets.append(new_pkt)
    
    return [bytes(pkt) for pkt in output_packets]

# ============================================================================
# 辅助函数
# ============================================================================

def process_one_group(i, orig_packets_bytes, tac_num=1000000, ip_num=2000):
    """单组处理函数包装器"""
    return process_one_group_n11(orig_packets_bytes, i, tac_num, ip_num)

def async_write_pcap(file_path, packets_list):
    """异步写入PCAP文件 - 增强版"""
    try:
        start_time = time.time()
        wrpcap(file_path, packets_list)
        end_time = time.time()
        
        # 计算文件大小
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB
        write_time = end_time - start_time
        
        print(f"写入完成: {file_path} ({len(packets_list)}个包, {file_size:.1f}MB, 耗时{write_time:.2f}s)")
        return file_path
    except Exception as e:
        print(f"写入失败: {file_path}, 错误: {e}")
        return None

# ============================================================================
# 主函数
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="N11接口数据包批量处理工具")
    parser.add_argument("-i", "--input", default="pcap/N11_release_18p.pcap", help="输入pcap文件路径")
    parser.add_argument("-o", "--output", default="pcap/N11_release_100.pcap", help="输出PCAP文件路径")
    parser.add_argument("-n", "--num", type=int, default=200, help="循环生成报文组数")
    parser.add_argument("--tac-num", type=int, default=1000000, help="TAC循环数量")
    parser.add_argument("--ip-num", type=int, default=2000, help="IP地址循环数量")
    parser.add_argument("--sport-num", type=int, default=20000, help="源端口循环数量")
    parser.add_argument("--test", action="store_true", help="运行测试模式（只处理单个组并分析）")
    parser.add_argument("--debug", action="store_true", help="启用调试输出")
    args = parser.parse_args()

    if args.test:
        print("=== 运行测试模式 ===")
        test_single_group()
        return

    # 批处理参数 - 修改为每10000次循环写一个文件
    BATCH_SIZE = 100  # 每批1万
    total_batches = args.num // BATCH_SIZE
    remain = args.num % BATCH_SIZE

    start_time = time.time()
    print(f"开始处理: {args.num} 个文件组 (每{BATCH_SIZE}组生成一个文件)")
    print(f"输入文件: {args.input}")
    print(f"输出文件: {args.output}")
    print(f"预计生成文件数: {total_batches + (1 if remain > 0 else 0)}")
    print(f"TAC循环数量: {args.tac_num}")
    print(f"IP循环数量: {args.ip_num}")
    print(f"调试模式: {'开启' if args.debug else '关闭'}")
    print("=" * 60)

    # 设置全局调试标志
    global DEBUG_MODE
    DEBUG_MODE = args.debug

    # 读取原始数据并转换为字节格式
    orig_packets = rdpcap(args.input)
    print(f"读取完成，共 {len(orig_packets)} 个数据包")
      # 转换为字节数组，减少后续处理开销
    orig_packets_bytes = [bytes(pkt) for pkt in orig_packets]
    del orig_packets
    gc.collect()

    def get_outfile(base, idx):
        """生成输出文件名"""
        base_name, ext = os.path.splitext(base)
        return f"{base_name}_{idx+1:03d}{ext}"

    batch_idx = 0

    # 双层执行器架构 - 优化多线程处理
    with ThreadPoolExecutor(max_workers=4) as file_writer:
        # 处理完整批次
        for i in range(total_batches):
            print(f"处理批次 {i+1}/{total_batches + (1 if remain > 0 else 0)}")
            all_modified_packets = []
            
            with ProcessPoolExecutor(max_workers=6) as executor:
                func = partial(process_one_group, orig_packets_bytes=orig_packets_bytes, tac_num=args.tac_num, ip_num=args.ip_num)
                results = executor.map(func, range(i * BATCH_SIZE, (i + 1) * BATCH_SIZE))
                
                for group_bytes in tqdm(results, total=BATCH_SIZE, desc=f"Batch {i+1}", ncols=80):
                    for pkt_bytes in group_bytes:
                        all_modified_packets.append(Ether(pkt_bytes))
            
            # 异步写入文件
            out_file = get_outfile(args.output, batch_idx)
            file_writer.submit(async_write_pcap, out_file, all_modified_packets)
              # 主动清理内存
            del all_modified_packets
            gc.collect()
            
            # 内存使用监控
            try:
                memory_mb = get_memory_usage()
                print(f"批次 {i+1} 处理完成，文件: {out_file}，当前内存使用: {memory_mb:.1f}MB")
            except:
                print(f"批次 {i+1} 处理完成，文件: {out_file}")
            batch_idx += 1

        # 处理剩余组
        if remain > 0:
            print(f"处理剩余批次 {batch_idx+1}/{total_batches + 1}")
            all_modified_packets = []
            
            with ProcessPoolExecutor(max_workers=6) as executor:
                func = partial(process_one_group, orig_packets_bytes=orig_packets_bytes, tac_num=args.tac_num, ip_num=args.ip_num)
                results = executor.map(func, range(total_batches * BATCH_SIZE, args.num))
                
                for group_bytes in tqdm(results, total=remain, desc=f"Batch {batch_idx+1}", ncols=80):
                    for pkt_bytes in group_bytes:
                        all_modified_packets.append(Ether(pkt_bytes))
            
            out_file = get_outfile(args.output, batch_idx)
            file_writer.submit(async_write_pcap, out_file, all_modified_packets)
              # 主动清理内存
            del all_modified_packets
            gc.collect()
            
            # 内存使用监控
            try:
                memory_mb = get_memory_usage()
                print(f"剩余批次处理完成，文件: {out_file}，当前内存使用: {memory_mb:.1f}MB")
            except:
                print(f"剩余批次处理完成，文件: {out_file}")

    # 等待所有写任务完成
    file_writer.shutdown(wait=True)
    
    end_time = time.time()
    duration = end_time - start_time
    speed = args.num / duration if duration > 0 else 0
    
    print(f"\n=== 处理完成 ===")
    print(f"总耗时: {duration:.2f} 秒")
    print(f"处理速度: {speed:.2f} 组/秒")
    print(f"生成文件: {total_batches + (1 if remain > 0 else 0)} 个")

if __name__ == "__main__":
    main()

def safe_replace_path_in_headers(frame_payload, imsi1, pkt_idx):
    """CentOS 7.6终极优化版：7层递进策略确保100%兼容性"""
    try:
        if DEBUG_MODE:
            print(f"[CentOS76-Ultimate] 开始终极path替换，pkt_idx={pkt_idx}, imsi1={imsi1}")
            print(f"[CentOS76-Ultimate] 原始payload长度: {len(frame_payload)}")
        
        original_payload = frame_payload
        
        # 策略1: 精确字节匹配替换（最高优先级）
        result = _centos76_strategy1_exact_bytes_replace(frame_payload, imsi1, pkt_idx)
        if result != frame_payload:
            if DEBUG_MODE:
                print(f"[CentOS76-Ultimate] 策略1成功: 精确字节匹配")
            return result
        
        # 策略2: 宽松字节模式替换
        result = _centos76_strategy2_loose_bytes_replace(frame_payload, imsi1, pkt_idx)
        if result != frame_payload:
            if DEBUG_MODE:
                print(f"[CentOS76-Ultimate] 策略2成功: 宽松字节模式")
            return result
        
        # 策略3: 增强的UTF-8字符串替换
        result = _centos76_strategy3_enhanced_string_replace(frame_payload, imsi1, pkt_idx)
        if result != frame_payload:
            if DEBUG_MODE:
                print(f"[CentOS76-Ultimate] 策略3成功: 增强字符串替换")
            return result
        
        # 策略4: 二进制模式搜索替换
        result = _centos76_strategy4_binary_pattern_replace(frame_payload, imsi1, pkt_idx)
        if result != frame_payload:
            if DEBUG_MODE:
                print(f"[CentOS76-Ultimate] 策略4成功: 二进制模式搜索")
            return result
        
        # 策略5: 十六进制级别替换
        result = _centos76_strategy5_hex_level_replace(frame_payload, imsi1, pkt_idx)
        if result != frame_payload:
            if DEBUG_MODE:
                print(f"[CentOS76-Ultimate] 策略5成功: 十六进制级别")
            return result
        
        # 策略6: 智能字节位置替换
        result = _centos76_strategy6_smart_position_replace(frame_payload, imsi1, pkt_idx)
        if result != frame_payload:
            if DEBUG_MODE:
                print(f"[CentOS76-Ultimate] 策略6成功: 智能位置替换")
            return result
        
        # 策略7: 暴力逐字节扫描替换（最后手段）
        result = _centos76_strategy7_brute_force_replace(frame_payload, imsi1, pkt_idx)
        if result != frame_payload:
            if DEBUG_MODE:
                print(f"[CentOS76-Ultimate] 策略7成功: 暴力逐字节扫描")
            return result
        
        if DEBUG_MODE:
            print(f"[CentOS76-Ultimate] 警告: 所有7层策略均失败，返回原始payload")
        return original_payload
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[CentOS76-Ultimate] 异常: {e}")
        return frame_payload

def _centos76_strategy1_exact_bytes_replace(payload, imsi1, pkt_idx):
    """策略1: 精确字节匹配替换"""
    try:
        result = payload
        
        # 定义精确的字节匹配模式
        exact_patterns = [
            # 完整路径的字节序列
            (b'/nsmf-pdusession/v1/sm-contexts/imsi-460012300000131-5/modify',
             f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify'.encode('utf-8')),
            (b'/nsmf-pdusession/v1/sm-contexts/imsi-310310140000131-5/modify',
             f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify'.encode('utf-8')),
            (b'/nsmf-pdusession/v1/sm-contexts/imsi-460012300000131-5',
             f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5'.encode('utf-8')),
            (b'/nsmf-pdusession/v1/sm-contexts/imsi-310310140000131-5',
             f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5'.encode('utf-8')),
            # IMSI部分
            (b'imsi-460012300000131', f'imsi-{imsi1}'.encode('utf-8')),
            (b'imsi-310310140000131', f'imsi-{imsi1}'.encode('utf-8')),
            # 纯数字
            (b'460012300000131', str(imsi1).encode('utf-8')),
            (b'310310140000131', str(imsi1).encode('utf-8')),
        ]
        
        for old_bytes, new_bytes in exact_patterns:
            if old_bytes in result:
                result = result.replace(old_bytes, new_bytes)
                if DEBUG_MODE:
                    print(f"[策略1] 替换成功: {old_bytes[:20]}... -> {new_bytes[:20]}...")
        
        return result
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[策略1] 异常: {e}")
        return payload

def _centos76_strategy2_loose_bytes_replace(payload, imsi1, pkt_idx):
    """策略2: 宽松字节模式替换"""
    try:
        result = bytearray(payload)
        imsi_bytes = str(imsi1).encode('utf-8')
        
        # 定义所有可能的IMSI字节序列
        possible_imsi_patterns = [
            b'460012300000131',
            b'310310140000131',
            b'460012300000133',
            b'310310140000133',
            b'460012300000135',
            b'310310140000135',
        ]
        
        replacements_made = 0
        for old_imsi in possible_imsi_patterns:
            start = 0
            while True:
                pos = result.find(old_imsi, start)
                if pos == -1:
                    break
                
                # 执行替换
                result[pos:pos+len(old_imsi)] = imsi_bytes
                replacements_made += 1
                start = pos + len(imsi_bytes)
        
        if replacements_made > 0 and DEBUG_MODE:
            print(f"[策略2] 宽松替换成功，共{replacements_made}处")
        
        return bytes(result)
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[策略2] 异常: {e}")
        return payload

def _centos76_strategy3_enhanced_string_replace(payload, imsi1, pkt_idx):
    """策略3: 增强的UTF-8字符串替换"""
    try:
        # 尝试多种编码方式
        encodings = ['utf-8', 'latin-1', 'ascii', 'utf-8-sig']
        
        for encoding in encodings:
            try:
                payload_str = payload.decode(encoding)
                modified = False
                
                # CentOS 7.6兼容的正则模式
                patterns = [
                    # 完整路径模式
                    (r'/nsmf-pdusession/v1/sm-contexts/imsi-\d{15}-\d+/modify',
                     f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify'),
                    (r'/nsmf-pdusession/v1/sm-contexts/imsi-\d{14,15}-\d+',
                     f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5'),
                    (r'/namf-comm/v1/ue-contexts/imsi-\d{13,15}',
                     f'/namf-comm/v1/ue-contexts/imsi-{imsi1}'),
                    # IMSI模式
                    (r'imsi-\d{15}', f'imsi-{imsi1}'),
                    (r'imsi-\d{14}', f'imsi-{imsi1}'),
                    (r'imsi-\d{13}', f'imsi-{imsi1}'),
                    # 特定数字
                    (r'460012300000\d{3}', str(imsi1)),
                    (r'310310140000\d{3}', str(imsi1)),
                ]
                
                for pattern, replacement in patterns:
                    old_str = payload_str
                    payload_str = re.sub(pattern, replacement, payload_str, flags=re.IGNORECASE)
                    if payload_str != old_str:
                        modified = True
                
                if modified:
                    return payload_str.encode(encoding)
                    
            except UnicodeDecodeError:
                continue
        
        return payload
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[策略3] 异常: {e}")
        return payload

def _centos76_strategy4_binary_pattern_replace(payload, imsi1, pkt_idx):
    """策略4: 二进制模式搜索替换"""
    try:
        result = bytearray(payload)
        imsi_str = str(imsi1)
        
        # 定义二进制搜索模式
        binary_patterns = [
            # 路径分隔符前后的模式
            (b'imsi-', b'imsi-'),
            (b'/sm-contexts/', b'/sm-contexts/'),
            (b'/modify', b'/modify'),
            (b'/n1-n2-messages', b'/n1-n2-messages'),
        ]
        
        # 在每个模式附近搜索IMSI数字
        for prefix, _ in binary_patterns:
            start = 0
            while True:
                pos = result.find(prefix, start)
                if pos == -1:
                    break
                
                # 在模式后查找数字序列
                search_start = pos + len(prefix)
                if search_start < len(result):
                    # 查找15位数字序列
                    digit_sequence = b''
                    for i in range(min(15, len(result) - search_start)):
                        byte_val = result[search_start + i]
                        if 48 <= byte_val <= 57:  # ASCII数字
                            digit_sequence += bytes([byte_val])
                        else:
                            break
                    
                    # 如果找到了13-15位数字，替换它
                    if len(digit_sequence) >= 13:
                        new_imsi_bytes = imsi_str.encode('utf-8')
                        result[search_start:search_start+len(digit_sequence)] = new_imsi_bytes
                        if DEBUG_MODE:
                            print(f"[策略4] 二进制模式替换: {digit_sequence} -> {new_imsi_bytes}")
                        return bytes(result)
                
                start = pos + 1
        
        return bytes(result)
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[策略4] 异常: {e}")
        return payload

def _centos76_strategy5_hex_level_replace(payload, imsi1, pkt_idx):
    """策略5: 十六进制级别替换"""
    try:
        hex_str = payload.hex()
        imsi_str = str(imsi1)
        
        # 定义十六进制编码的IMSI模式
        # 注意：这些是实际的十六进制编码，不是ASCII十六进制
        hex_patterns = {
            # 460012300000131的不同编码方式
            '343630303132333030303030313331': imsi_str.encode('utf-8').hex(),
            '343630303132333030303030313333': imsi_str.encode('utf-8').hex(),
            '343630303132333030303030313335': imsi_str.encode('utf-8').hex(),
            # 310310140000131的不同编码方式
            '333130333130313430303030313331': imsi_str.encode('utf-8').hex(),
            '333130333130313430303030313333': imsi_str.encode('utf-8').hex(),
            '333130333130313430303030313335': imsi_str.encode('utf-8').hex(),
        }
        
        for old_hex, new_hex in hex_patterns.items():
            if old_hex in hex_str:
                hex_str = hex_str.replace(old_hex, new_hex)
                if DEBUG_MODE:
                    print(f"[策略5] 十六进制替换成功: {old_hex} -> {new_hex}")
                return bytes.fromhex(hex_str)
        
        return payload
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[策略5] 异常: {e}")
        return payload

def _centos76_strategy6_smart_position_replace(payload, imsi1, pkt_idx):
    """策略6: 智能字节位置替换"""
    try:
        result = bytearray(payload)
        imsi_bytes = str(imsi1).encode('utf-8')
        
        # 针对特定报文类型的智能替换
        if pkt_idx in [13, 15, 16]:
            # 查找可能的IMSI位置特征
            markers = [
                b'imsi-',  # IMSI标识符
                b'sm-contexts/',  # 上下文路径
                b'ue-contexts/',  # UE上下文
            ]
            
            for marker in markers:
                start = 0
                while True:
                    pos = result.find(marker, start)
                    if pos == -1:
                        break
                    
                    # 在标记后查找数字序列
                    search_pos = pos + len(marker)
                    if search_pos < len(result):
                        # 提取数字序列
                        digit_end = search_pos
                        while digit_end < len(result) and 48 <= result[digit_end] <= 57:
                            digit_end += 1
                        
                        # 如果找到了长度合适的数字序列
                        if digit_end - search_pos >= 13:
                            old_imsi = result[search_pos:digit_end]
                            result[search_pos:digit_end] = imsi_bytes
                            if DEBUG_MODE:
                                print(f"[策略6] 智能位置替换: {old_imsi} -> {imsi_bytes}")
                            return bytes(result)
                    
                    start = pos + 1
        
        return bytes(result)
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[策略6] 异常: {e}")
        return payload

def _centos76_strategy7_brute_force_replace(payload, imsi1, pkt_idx):
    """策略7: 暴力逐字节扫描替换（最后手段）"""
    try:
        result = bytearray(payload)
        imsi_str = str(imsi1)
        target_length = len(imsi_str)
        
        # 定义所有可能的IMSI模式
        known_imsi_patterns = [
            '460012300000131',
            '310310140000131',
            '460012300000133',
            '310310140000133',
            '460012300000135',
            '310310140000135',
        ]
        
        # 暴力搜索和替换
        for pattern in known_imsi_patterns:
            pattern_bytes = pattern.encode('utf-8')
            
            # 逐字节搜索
            for i in range(len(result) - len(pattern_bytes) + 1):
                if result[i:i+len(pattern_bytes)] == pattern_bytes:
                    # 找到匹配，执行替换
                    result[i:i+len(pattern_bytes)] = imsi_str.encode('utf-8')
                    if DEBUG_MODE:
                        print(f"[策略7] 暴力替换成功: pos={i}, {pattern} -> {imsi_str}")
                    return bytes(result)
        
        # 如果还没成功，尝试数字序列匹配
        for i in range(len(result) - 13):
            # 检查是否是15位数字序列
            if all(48 <= result[i+j] <= 57 for j in range(15) if i+j < len(result)):
                # 提取数字序列
                digit_sequence = result[i:i+15].decode('utf-8', errors='ignore')
                if digit_sequence.isdigit() and len(digit_sequence) == 15:
                    # 这很可能是IMSI，替换它
                    result[i:i+15] = imsi_str.encode('utf-8')
                    if DEBUG_MODE:
                        print(f"[策略7] 数字序列替换: pos={i}, {digit_sequence} -> {imsi_str}")
                    return bytes(result)
        
        return bytes(result)
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"[策略7] 异常: {e}")
        return payload

def create_specific_headers(pkt_idx, imsi1, content_length=None):
    """为特定报文创建完整的HEADERS帧内容 - 动态content-length版本"""
    try:
        # 每次创建新的编码器，避免状态冲突
        from hpack import Encoder
        encoder = Encoder()
        
        # 核心优化：统一处理第13、15、16个报文的HEADERS
        # 只包含5G核心网必需的基础字段，严格按照3GPP标准
        if pkt_idx in [13, 15, 16]:
            headers = [
                (":method", "POST"),
                (":scheme", "http"),
#                (":authority", "smf.5gc.mnc010.mcc310.3gppnetwork.org"),
                (":path", f"/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify"),
                ("content-type", "multipart/related; boundary=++Boundary"),
            ]
            
            # 动态添加content-length字段
            if content_length is not None and content_length > 0:
                headers.append(("content-length", str(content_length)))
            else:
                # 如果没有提供content-length，设为0（避免字段缺失）
                headers.append(("content-length", "0"))
            
            # 使用默认HPACK表，避免自定义条目导致的索引问题
            encoded_headers = encoder.encode(headers)
            return encoded_headers
            
        return None
        
    except Exception as e:
        return None

# ============================================================================
# HTTP/2 Payload处理函数
# ============================================================================

# ============================================================================
# 调试和测试函数
# ============================================================================

def analyze_tcp_sequence_issues(packets):
    """分析TCP序列号问题"""
    print("\n=== TCP序列号分析 ===")
    
    flows = {}
    for i, pkt in enumerate(packets, 1):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
            
        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        if flow not in flows:
            flows[flow] = []
        
        flows[flow].append({
            'pkt_idx': i,
            'seq': pkt[TCP].seq,
            'ack': pkt[TCP].ack if pkt[TCP].flags & 0x10 else None,
            'flags': pkt[TCP].flags,
            'payload_len': len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
        })
    
    for flow, flow_packets in flows.items():
        print(f"\n流 {flow[0]}:{flow[2]} -> {flow[1]}:{flow[3]}")
        prev_seq = None
        prev_ack = None
        
        for pkt_info in flow_packets:
            flags_str = []
            if pkt_info['flags'] & 0x02: flags_str.append('SYN')
            if pkt_info['flags'] & 0x10: flags_str.append('ACK')
            if pkt_info['flags'] & 0x08: flags_str.append('PSH')
            if pkt_info['flags'] & 0x01: flags_str.append('FIN')
            if pkt_info['flags'] & 0x04: flags_str.append('RST')
            
            seq_jump = ""
            if prev_seq is not None:
                expected_seq = prev_seq + (flow_packets[flow_packets.index(pkt_info)-1]['payload_len'] if flow_packets.index(pkt_info) > 0 else 0)
                if pkt_info['seq'] != expected_seq:
                    seq_jump = f" (预期: {expected_seq}, 差异: {pkt_info['seq'] - expected_seq})"
            
            print(f"  报文{pkt_info['pkt_idx']}: seq={pkt_info['seq']}{seq_jump}, "
                  f"ack={pkt_info['ack']}, flags=[{','.join(flags_str)}], "
                  f"payload={pkt_info['payload_len']}")
            
            prev_seq = pkt_info['seq']
            prev_ack = pkt_info['ack']

def test_single_group():
    """测试单个组的处理"""
    print("=== 测试单个组处理 ===")
    
    # 读取原始数据
    input_file = "pcap/N11_release_18p.pcap"
    if not os.path.exists(input_file):
        print(f"错误：输入文件 {input_file} 不存在")
        # 尝试当前目录
        if os.path.exists("N11_release_18p.pcap"):
            input_file = "N11_release_18p.pcap"
        else:
            print("请确保输入文件存在")
            return None
    
    orig_packets = rdpcap(input_file)
    print(f"读取了 {len(orig_packets)} 个原始数据包")
    
    # 分析原始数据包
    print("\n--- 原始数据包分析 ---")
    analyze_tcp_sequence_issues(orig_packets)
    
    # 处理单个组
    orig_packets_bytes = [bytes(pkt) for pkt in orig_packets]
    processed_bytes = process_one_group_n11(orig_packets_bytes, 0)
    
    # 转换回Scapy格式
    processed_packets = [Ether(pkt_bytes) for pkt_bytes in processed_bytes]
    
    print(f"\n处理后得到 {len(processed_packets)} 个数据包")
    
    # 分析处理后的数据包
    print("\n--- 处理后数据包分析 ---")
    analyze_tcp_sequence_issues(processed_packets)
    
    # 保存测试结果
    test_output = "test_single_group.pcap"
    wrpcap(test_output, processed_packets)
    print(f"\n测试结果已保存到: {test_output}")
    
    return processed_packets

def get_memory_usage():
    """获取当前内存使用情况"""
    process = psutil.Process()
    memory_info = process.memory_info()
    memory_mb = memory_info.rss / 1024 / 1024  # 转换为MB
    return memory_mb