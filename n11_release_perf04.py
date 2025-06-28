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

def update_global_vars(i, tac_num=10000000, ip_num=2000, sport_num=20000):
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
      # 生成递增的参数，sip1使用ip_num循环，dip1保持固定
    sip1 = inc_ip(base["sip1"], i % ip_num)
    dip1 = base["dip1"]  # 保持固定值
    sport1 = inc_int(str(base["sport1"]), i % sport_num)
    cgi1 = format(int(format(base["cgi1"], 'x'), 16) + i, 'x').lower().zfill(9)  # 固定9个字符，小写
    tac1 = format(int(format(base["tac1"], 'x'), 16) + (i % tac_num), 'x').lower().zfill(6)  # 固定6个字符，小写
    imsi1 = inc_int(str(base["imsi1"]), i)
    
    return sip1, dip1, sport1, cgi1, tac1, imsi1

def process_multipart_content(content, cgi1, tac1, imsi1, pkt_idx):
    """严格处理multipart内容，确保boundary、换行、结尾完全符合协议，避免Malformed Packet"""
    try:
        if DEBUG_MODE:
            print(f"Debug: pkt_idx={pkt_idx}, 开始处理multipart内容, cgi1={cgi1}, tac1={tac1}, imsi1={imsi1}")
        # 以字节模式处理
        if isinstance(content, str):
            content_bytes = content.encode('utf-8', errors='replace')
        else:
            content_bytes = content
        # boundary查找
        import re
        m = re.search(br'\r?\n(--[\w\+]+)', content_bytes)
        if m:
            boundary = m.group(1)
        else:
            # fallback: 取默认
            boundary = b'--++Boundary'
        # 分割parts（严格以\r\n--boundary分割）
        parts = re.split(br'\r?\n' + re.escape(boundary) + br'(?:--)?\r?\n', content_bytes)
        # 过滤空part
        real_parts = [p for p in parts if p.strip() and not p.strip().startswith(boundary + b'--')]
        modified_parts = []
        for part in real_parts:
            # 头和内容分割
            header_end = part.find(b'\r\n\r\n')
            if header_end == -1:
                header_end = part.find(b'\n\n')
                if header_end == -1:
                    modified_parts.append(part)
                    continue
                header_bytes = part[:header_end+2]
                body_bytes = part[header_end+2:]
            else:
                header_bytes = part[:header_end+4]
                body_bytes = part[header_end+4:]
            # 判断是否JSON
            if b'application/json' in header_bytes.lower():
                try:
                    body_str = body_bytes.decode('utf-8', errors='ignore')
                    json_start = body_str.find('{')
                    json_end = body_str.rfind('}')
                    if json_start != -1 and json_end > json_start:
                        json_content = body_str[json_start:json_end+1]
                        json_data = json.loads(json_content)
                        modified = False
                        # 修改ueLocation
                        if 'ueLocation' in json_data and isinstance(json_data['ueLocation'], dict):
                            ue_location = json_data['ueLocation']
                            if 'nrLocation' in ue_location and isinstance(ue_location['nrLocation'], dict):
                                nr_location = ue_location['nrLocation']
                                if 'ncgi' in nr_location and isinstance(nr_location['ncgi'], dict):
                                    nr_location['ncgi']['nrCellId'] = cgi1
                                    modified = True
                                if 'tai' in nr_location and isinstance(nr_location['tai'], dict):
                                    nr_location['tai']['tac'] = tac1
                                    modified = True
                        # 修改SUPI和GPSI
                        if 'supi' in json_data:
                            json_data['supi'] = f"imsi-{imsi1}"
                            modified = True
                        if 'gpsi' in json_data:
                            json_data['gpsi'] = f"msisdn-{imsi1}"
                            modified = True
                        if modified:
                            new_json = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False)
                            # 保持原有前后内容
                            new_body = body_str[:json_start] + new_json + body_str[json_end+1:]
                            body_bytes = new_body.encode('utf-8')
                except Exception as e:
                    if DEBUG_MODE:
                        print(f"JSON patch error: {e}")
            # 重新组装part
            modified_parts.append(header_bytes + body_bytes)
        # 组装multipart
        # 每个part前加\r\n--boundary，首个前不加
        multipart = b''
        for i, part in enumerate(modified_parts):
            if i == 0:
                multipart += boundary + b'\r\n' + part
            else:
                multipart += b'\r\n' + boundary + b'\r\n' + part
        # 结尾加\r\n--boundary--\r\n
        multipart += b'\r\n' + boundary + b'--\r\n'
        return multipart if not isinstance(content, str) else multipart.decode('utf-8', errors='replace')
    except Exception as e:
        if DEBUG_MODE:
            print(f"process_multipart_content异常: {e}")
        return content if isinstance(content, str) else content.decode('utf-8', errors='replace')

def modify_http_path(path, imsi1, pkt_idx, pdusessionId="5"):
    """修改HTTP路径中的IMSI部分 - 支持多种格式和更宽泛IMSI长度"""
    try:
        original_path = path
        
        # 针对第13、15、16个报文的特殊处理
        if pkt_idx in [13, 15, 16]:
            # 这些报文的path都应该统一为相同格式
            target_path = f"/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-{pdusessionId}/modify"
            if path != target_path:
                return target_path
            return path
        
        # 模式1: /nsmf-pdusession/v1/sm-contexts/imsi-数字-数字/modify
        pattern1 = r'(/nsmf-pdusession/v1/sm-contexts/)imsi-(\d+)-(\d+)(/modify)'
        match = re.search(pattern1, path)
        if match:
            new_path = re.sub(pattern1, rf'\1imsi-{imsi1}-{pdusessionId}\4', path)
            return new_path
        
        # 模式2: /nsmf-pdusession/v1/sm-contexts/imsi-数字-数字 (无/modify)
        pattern2 = r'(/nsmf-pdusession/v1/sm-contexts/)imsi-(\d+)-(\d+)(?=/|$)'
        match = re.search(pattern2, path)
        if match:
            new_path = re.sub(pattern2, rf'\1imsi-{imsi1}-{pdusessionId}', path)
            return new_path
        
        # 模式3: /nsmf-pdusession/v1/sm-contexts (无IMSI部分，添加完整路径)
        pattern3 = r'^/nsmf-pdusession/v1/sm-contexts$'
        match = re.search(pattern3, path)
        if match:
            new_path = f"/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-{pdusessionId}/modify"
            return new_path
          # 模式4: /namf-comm/v1/ue-contexts/imsi-数字-数字/n1-n2-messages
        pattern4 = r'(/namf-comm/v1/ue-contexts/)imsi-(\d+)-(\d+)(/n1-n2-messages)'
        match = re.search(pattern4, path)
        if match:
            new_path = re.sub(pattern4, rf'\1imsi-{imsi1}-\3\4', path)  # 保持原有的数字后缀
            return new_path
        
        # 模式5: /namf-comm/v1/ue-contexts/imsi-数字 (无-数字后缀)
        pattern5 = r'(/namf-comm/v1/ue-contexts/)imsi-(\d+)(?=/|$)'
        match = re.search(pattern5, path)
        if match:
            new_path = re.sub(pattern5, rf'\1imsi-{imsi1}', path)  # 不添加后缀
            return new_path
        
        # 模式6: supi-数字 格式
        pattern6 = r'(supi-)(\d+)'
        match = re.search(pattern6, path)
        if match:
            new_path = re.sub(pattern6, rf'supi-{imsi1}', path)
            return new_path
        
        # 模式7: 通用IMSI替换 (兜底，支持10-20位IMSI)
        pattern7 = r'imsi-(\d{10,20})'
        match = re.search(pattern7, path)
        if match:
            new_path = re.sub(pattern7, f'imsi-{imsi1}', path)
            return new_path
            
        return path
    except Exception as e:
        if DEBUG_MODE:
            print(f"modify_http_path 异常: {e}")
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
                                print(f"策略1失败: pkt_idx={pkt_idx}, error={specific_error}")
                      
                    # 策略2: HPACK解码修改（兜底方案）
                    if not headers_processed and decoder:
                        try:                            # 重置解码器状态
                            from hpack import Decoder, Encoder
                            decoder = Decoder()  # 创建新实例避免状态冲突
                            encoder = Encoder()
                            
                            headers = decoder.decode(frame['payload'])
                            new_headers = []
                            headers_modified_flag = False
                            
                            if DEBUG_MODE:
                                print(f"Debug: pkt_idx={pkt_idx}, 成功解码headers")
                            
                            for name, original_value in headers:
                                value = original_value
                                
                                # 关键字段修改
                                if name.lower() == ':path':
                                    if isinstance(value, bytes):
                                        path_str = value.decode('utf-8', errors='ignore')
                                    else:
                                        path_str = str(value)
                                    
                                    if DEBUG_MODE:
                                        print(f"Debug: 原始path={path_str}")
                                    
                                    new_path = modify_http_path(path_str, imsi1, pkt_idx)
                                    if new_path != path_str:
                                        value = new_path.encode('utf-8') if isinstance(original_value, bytes) else new_path
                                        headers_modified_flag = True
                                        if DEBUG_MODE:
                                            print(f"Debug: 新path={new_path}")
                                
                                elif name.lower() == 'location':
                                    if isinstance(value, bytes):
                                        location_str = value.decode('utf-8', errors='ignore')
                                    else:
                                        location_str = str(value)
                                    
                                    new_location = re.sub(r'imsi-(\d+)', rf'imsi-{imsi1}', location_str)
                                    if new_location != location_str:
                                        value = new_location.encode('utf-8') if isinstance(original_value, bytes) else new_location
                                        headers_modified_flag = True
                                
                                # 更新content-length字段
                                elif name.lower() == 'content-length' and pkt_idx in [13, 15, 16]:
                                    total_data_length = sum(info['length'] for info in processed_data_frames.values())
                                    if total_data_length > 0:
                                        value = str(total_data_length).encode('utf-8') if isinstance(original_value, bytes) else str(total_data_length)
                                        headers_modified_flag = True
                                
                                new_headers.append((name, value))
                              # 重新编码修改后的headers
                            if headers_modified_flag:
                                modified_payload = encoder.encode(new_headers)
                                headers_processed = True
                                if DEBUG_MODE:
                                    print(f"Debug: pkt_idx={pkt_idx}, HPACK编码成功")
                            
                        except Exception as hpack_error:
                            if DEBUG_MODE:
                                print(f"策略2(HPACK)失败: pkt_idx={pkt_idx}, error={hpack_error}")
                      # 策略3: 字节级替换（最后兜底）- CentOS兼容增强
                    if not headers_processed:
                        if DEBUG_MODE:
                            print(f"Debug: pkt_idx={pkt_idx}, 尝试字节级替换")
                        
                        # 首先尝试安全替换
                        byte_modified_payload = safe_replace_path_in_headers(frame['payload'], imsi1, pkt_idx)
                        if byte_modified_payload != frame['payload']:
                            modified_payload = byte_modified_payload
                            headers_processed = True
                            if DEBUG_MODE:
                                print(f"Debug: pkt_idx={pkt_idx}, 字节级替换成功")
                        else:
                            # CentOS兼容性增强：强制字符串替换
                            try:
                                payload_str = frame['payload'].decode('utf-8', errors='ignore')
                                # 多重路径替换策略
                                patterns = [
                                    (r'/nsmf-pdusession/v1/sm-contexts/imsi-\d+-\d+/modify', 
                                     f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify'),
                                    (r'imsi-\d+', f'imsi-{imsi1}'),
                                ]
                                
                                modified_str = payload_str
                                for pattern, replacement in patterns:
                                    new_str = re.sub(pattern, replacement, modified_str)
                                    if new_str != modified_str:
                                        modified_str = new_str
                                        headers_processed = True
                                        if DEBUG_MODE:
                                            print(f"Debug: pkt_idx={pkt_idx}, 强制字符串替换成功")
                                
                                if headers_processed:
                                    modified_payload = modified_str.encode('utf-8')
                                    
                            except Exception as force_error:
                                if DEBUG_MODE:
                                    print(f"Debug: pkt_idx={pkt_idx}, 强制替换失败: {force_error}")
                    
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

def process_one_group_n11(orig_packets_bytes, group_id, tac_num=10000000, ip_num=2000, sport_num=20000):
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

def process_one_group(i, orig_packets_bytes, tac_num=10000000, ip_num=2000):
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
    parser.add_argument("-o", "--output", default="pcap/N11_release_1w-merg.pcap", help="输出PCAP文件路径")
    parser.add_argument("-n", "--num", type=int, default=40000000, help="循环生成报文组数")
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
    BATCH_SIZE = 10000  # 每批1万
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
    """安全地在HEADERS帧中替换路径，支持多种IMSI格式和路径结构"""
    try:
        # 策略1: 字节级IMSI替换（支持多种长度）
        imsi_bytes = str(imsi1).encode('utf-8')
        patterns = [
            rb'imsi-\d{10,20}',
            rb'/nsmf-pdusession/v1/sm-contexts/imsi-\d{10,20}-\d+/modify',
            rb'/nsmf-pdusession/v1/sm-contexts/imsi-\d{10,20}-\d+',
            rb'/namf-comm/v1/ue-contexts/imsi-\d{10,20}',
        ]
        payload = frame_payload
        for pattern in patterns:
            payload, n = re.subn(pattern, lambda m: b'imsi-' + imsi_bytes if b'imsi-' in m.group(0) else imsi_bytes, payload)
            if n > 0:
                return payload
        # 策略2: 字符串正则替换
        try:
            payload_str = frame_payload.decode('utf-8', errors='ignore')
            patterns_str = [
                (r'imsi-\d{10,20}', f'imsi-{imsi1}'),
                (r'/nsmf-pdusession/v1/sm-contexts/imsi-\d{10,20}-\d+/modify', f'/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify'),
                (r'/namf-comm/v1/ue-contexts/imsi-\d{10,20}', f'/namf-comm/v1/ue-contexts/imsi-{imsi1}'),
            ]
            for pattern, repl in patterns_str:
                payload_str, n = re.subn(pattern, repl, payload_str)
                if n > 0:
                    return payload_str.encode('utf-8')
        except Exception as e:
            if DEBUG_MODE:
                print(f"safe_replace_path_in_headers 字符串替换异常: {e}")
        return frame_payload
    except Exception as e:
        if DEBUG_MODE:
            print(f"safe_replace_path_in_headers 异常: {e}")
        return frame_payload

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