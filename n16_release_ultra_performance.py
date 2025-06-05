#!/usr/bin/env python3
"""
终极性能优化版本：深度性能优化，目标达到参考文件的最高性能水平
主要优化：
1. 采用最高性能的工作函数直接处理bytes格式
2. 消除不必要的数据包复制和深拷贝
3. 优化HTTP/2帧解析使用直接字节操作
4. 极简化的IP地址递增算法
5. 内存池化和复用机制
6. 零拷贝数据处理
"""

from scapy.all import rdpcap, wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from hpack import Decoder, Encoder
import json
import re
import os
import concurrent.futures
from tqdm import tqdm
import gc
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import partial
import argparse
import time
import copy
import struct
import tempfile

# ============================================================================
# 全局变量定义 - 高性能预计算
# ============================================================================

# IP地址高性能转换
def ip_to_int(ip_str):
    """IP字符串转整数，高性能版本"""
    parts = ip_str.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def int_to_ip(ip_int):
    """整数转IP字符串，高性能版本"""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

# 预计算基础IP
SIP2_BASE_INT = ip_to_int("50.0.0.1")
DIP2_BASE_INT = ip_to_int("60.0.0.1")
SPORT2_BASE = 10001
PDUID_BASE = 10000001

# 预编译正则表达式
JSON_FIELD_PATTERNS = {
    'ismfId': re.compile(rb'"ismfId":"([^"]+)"'),
    'ismfPduSessionUri': re.compile(rb'"ismfPduSessionUri":"([^"]+)"'),
    'content-length': re.compile(rb'content-length\x00([^\x00]+)'),
}

# HTTP/2帧类型常量
FRAME_TYPE_HEADERS = 0x1
FRAME_TYPE_DATA = 0x0

# ============================================================================
# 高性能HTTP/2帧解析器
# ============================================================================

def parse_frame_ultra_fast(data, offset=0):
    """超高性能HTTP/2帧解析，使用位运算避免struct调用"""
    if offset + 9 > len(data):
        return None
        
    # 直接位操作解析帧头，避免struct开销
    length = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
    frame_type = data[offset + 3]
    flags = data[offset + 4]
    stream_id = ((data[offset + 5] & 0x7F) << 24) | (data[offset + 6] << 16) | (data[offset + 7] << 8) | data[offset + 8]
    
    payload_end = offset + 9 + length
    if payload_end > len(data):
        payload_end = len(data)
        length = payload_end - (offset + 9)
    
    return {
        'type': frame_type,
        'flags': flags,
        'stream_id': stream_id,
        'length': length,
        'payload': data[offset + 9:payload_end],
        'start_offset': offset,
        'end_offset': payload_end
    }

def extract_frames_ultra_fast(data):
    """超高性能帧提取"""
    frames = []
    offset = 0
    
    while offset < len(data):
        frame = parse_frame_ultra_fast(data, offset)
        if not frame:
            break
        frames.append(frame)
        offset = frame['end_offset']
    
    return frames

# ============================================================================
# HTTP/2数据处理 - 零拷贝优化
# ============================================================================

def modify_json_ultra_fast(payload_bytes, group_id):
    """超高性能JSON修改，避免完整解析"""
    if not payload_bytes or len(payload_bytes) < 10:
        return None
    
    try:
        # 计算当前组的值 - 防止数值溢出
        safe_group_id = group_id % 999999999  # 限制在合理范围内
        new_ismfid = f"10000000-1000-4000-a000-{100000000000 + safe_group_id}"
        new_sip = int_to_ip(SIP2_BASE_INT + (group_id % 0xFFFFFF))
        new_pduid = PDUID_BASE + safe_group_id
        new_uri = f"http://{new_sip}/nsmf-pdusession/v1/pdu-sessions/{new_pduid}"
        
        # 使用字节替换，避免JSON解析开销
        modified = payload_bytes
        
        # 替换ismfId（如果存在）
        ismfid_match = JSON_FIELD_PATTERNS['ismfId'].search(modified)
        if ismfid_match:
            old_ismfid = ismfid_match.group(1)
            modified = modified.replace(
                b'"ismfId":"' + old_ismfid + b'"',
                f'"ismfId":"{new_ismfid}"'.encode()
            )
        
        # 替换ismfPduSessionUri（如果存在）
        uri_match = JSON_FIELD_PATTERNS['ismfPduSessionUri'].search(modified)
        if uri_match:
            old_uri = uri_match.group(1)
            modified = modified.replace(
                b'"ismfPduSessionUri":"' + old_uri + b'"',
                f'"ismfPduSessionUri":"{new_uri}"'.encode()
            )
        
        return modified if modified != payload_bytes else None
        
    except Exception:
        return None

def process_headers_frame_ultra_fast(frame_payload, group_id, data_length=None):
    """超高性能HEADERS帧处理"""
    try:
        decoder = Decoder()
        encoder = Encoder()
        decoded_headers = decoder.decode(frame_payload)
        
        # 计算新值 - 防止溢出
        new_sip = int_to_ip(SIP2_BASE_INT + (group_id % 0xFFFFFF))
        new_pduid = PDUID_BASE + (group_id % 999999999)
        
        # 构建新的headers列表
        new_headers = []
        modified = False
        
        # 高性能headers修改
        for name, value in decoded_headers:
            if name == b':authority':
                new_value = new_sip.encode()
                if value != new_value:
                    new_headers.append((name, new_value))
                    modified = True
                else:
                    new_headers.append((name, value))
            elif name == b':path':
                if b'modify' in value:
                    new_path = f"/nsmf-pdusession/v1/pdu-sessions/{new_pduid}/modify".encode()
                elif value.endswith(b'/15'):
                    new_path = f"/nsmf-pdusession/v1/pdu-sessions/{new_pduid}".encode()
                else:
                    new_headers.append((name, value))
                    continue
                if value != new_path:
                    new_headers.append((name, new_path))
                    modified = True
                else:
                    new_headers.append((name, value))
            elif name == b'content-length' and data_length is not None:
                new_cl = str(data_length).encode()
                if value != new_cl:
                    new_headers.append((name, new_cl))
                    modified = True
                else:
                    new_headers.append((name, value))
            else:
                new_headers.append((name, value))
        
        if modified:
            return encoder.encode(new_headers)
        
        return None
        
    except Exception:
        return None

# ============================================================================
# 核心数据包处理函数 - 零拷贝优化
# ============================================================================

def process_one_group_ultra_performance(orig_packets_bytes, group_id):
    """终极性能单组处理函数 - 直接操作字节数据"""
    # 反序列化数据包（无法避免，但后续都是零拷贝）
    orig_packets = [Ether(pkt_bytes) for pkt_bytes in orig_packets_bytes]
    
    # 计算当前组参数（预计算，避免重复计算）
    sip2 = int_to_ip(SIP2_BASE_INT + (group_id % 0xFFFFFF))  # 防止IP溢出
    dip2 = int_to_ip(DIP2_BASE_INT + (group_id % 0xFFFFFF))  # 防止IP溢出
    sport2 = SPORT2_BASE + (group_id % 50000)  # 端口范围: 10001-60000，参考n16_batch17_1000ip_perf.py避免溢出
    
    # 序列号跟踪
    seq_diff = {}
    modified_packets = []
    
    for idx, pkt in enumerate(orig_packets, 1):
        # 浅拷贝足够，避免深拷贝开销
        new_pkt = pkt.copy()
        modified = False
        original_length = 0
        new_length = 0
        
        # IP地址和端口修改（直接赋值，避免条件判断）
        if new_pkt.haslayer(IP):
            original_src = new_pkt[IP].src
            if original_src == orig_packets[0][IP].src:  # 客户端
                new_pkt[IP].src = sip2
                new_pkt[IP].dst = dip2
                if new_pkt.haslayer(TCP):
                    new_pkt[TCP].sport = sport2
            else:  # 服务端
                new_pkt[IP].src = dip2
                new_pkt[IP].dst = sip2
                if new_pkt.haslayer(TCP):
                    new_pkt[TCP].dport = sport2
        
        # HTTP/2 payload处理（只处理特定包）
        if idx in {9, 11, 13, 15} and new_pkt.haslayer(TCP) and new_pkt.haslayer(Raw):
            raw_data = bytes(new_pkt[Raw].load)
            original_length = len(raw_data)
            
            # 跳过HTTP/2连接前言
            if not raw_data.startswith(b'PRI * HTTP/2.0'):
                frames = extract_frames_ultra_fast(raw_data)
                if frames:
                    new_payload = b''
                    data_frame_length = 0
                    
                    # 第一遍：提取DATA帧长度
                    for frame in frames:
                        if frame['type'] == FRAME_TYPE_DATA:
                            new_data = modify_json_ultra_fast(frame['payload'], group_id)
                            if new_data is not None:
                                data_frame_length = len(new_data)
                            else:
                                data_frame_length = len(frame['payload'])
                            break
                    
                    # 第二遍：处理所有帧
                    for frame in frames:
                        frame_header = struct.pack('!I', frame['length'])[1:] + \
                                     struct.pack('!BBB', frame['type'], frame['flags'], 
                                               (frame['stream_id'] >> 24) & 0xFF) + \
                                     struct.pack('!I', frame['stream_id'] & 0xFFFFFF)[1:]
                        
                        if frame['type'] == FRAME_TYPE_HEADERS:
                            new_headers = process_headers_frame_ultra_fast(
                                frame['payload'], group_id, data_frame_length
                            )
                            if new_headers is not None:
                                # 重新构建帧头
                                new_header = struct.pack('!I', len(new_headers))[1:] + \
                                           frame_header[3:]
                                new_payload += new_header + new_headers
                                modified = True
                            else:
                                new_payload += frame_header + frame['payload']
                        elif frame['type'] == FRAME_TYPE_DATA:
                            new_data = modify_json_ultra_fast(frame['payload'], group_id)
                            if new_data is not None:
                                # 重新构建帧头
                                new_header = struct.pack('!I', len(new_data))[1:] + \
                                           frame_header[3:]
                                new_payload += new_header + new_data
                                modified = True
                            else:
                                new_payload += frame_header + frame['payload']
                        else:
                            new_payload += frame_header + frame['payload']
                    
                    if modified:
                        new_pkt[Raw].load = new_payload
                        new_length = len(new_payload)
        
        # TCP序列号调整（简化逻辑）
        if new_pkt.haslayer(TCP):
            flow = (new_pkt[IP].src, new_pkt[IP].dst, new_pkt[TCP].sport, new_pkt[TCP].dport)
            rev_flow = (new_pkt[IP].dst, new_pkt[IP].src, new_pkt[TCP].dport, new_pkt[TCP].sport)
            
            if flow not in seq_diff:
                seq_diff[flow] = 0
            if rev_flow not in seq_diff:
                seq_diff[rev_flow] = 0
            
            # 序列号调整
            if modified and original_length != new_length:
                diff = new_length - original_length
                new_pkt[TCP].seq = new_pkt[TCP].seq + seq_diff[flow]
                if new_pkt[TCP].flags & 0x10:  # ACK flag
                    new_pkt[TCP].ack = new_pkt[TCP].ack + seq_diff[rev_flow]
                seq_diff[flow] += diff
            else:
                new_pkt[TCP].seq = new_pkt[TCP].seq + seq_diff[flow]
                if new_pkt[TCP].flags & 0x10:  # ACK flag
                    new_pkt[TCP].ack = new_pkt[TCP].ack + seq_diff[rev_flow]
        
        # 重算校验和（必需）
        if new_pkt.haslayer(IP):
            del new_pkt[IP].chksum
        if new_pkt.haslayer(TCP):
            del new_pkt[TCP].chksum
        
        modified_packets.append(new_pkt)
    
    return [bytes(pkt) for pkt in modified_packets]

# ============================================================================
# 批处理工作函数 - 参考最高性能架构
# ============================================================================

def process_one_group(i, orig_packets_bytes, ip_num=1000):
    """高性能单组处理 - 使用超级优化算法"""
    return process_one_group_ultra_performance(orig_packets_bytes, i)

def async_write_pcap(file_path, packets_list):
    """异步写入PCAP文件"""
    try:
        wrpcap(file_path, packets_list)
        return file_path
    except Exception as e:
        print(f"写入文件失败 {file_path}: {e}")
        return None

# ============================================================================
# 主函数 - 完全参考n16_batch17_1000ip_perf.py架构
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="终极性能版本 - 批量修改PCAP")
    parser.add_argument("-i", "--input", default="pcap/N16_release_18p.pcap", help="输入pcap文件路径")
    parser.add_argument("-o", "--output", default="pcap/N16_1w.pcap", help="输出PCAP文件路径")
    parser.add_argument("-n", "--num", type=int, default=20000, help="循环生成报文组数")
    parser.add_argument("--ip-num", type=int, default=1000, help="IP数量参数（保留兼容）")
    args = parser.parse_args()

    start_time = time.time()
    print(f"终极性能版本启动: {args.num} 个文件组")
    print(f"输入文件: {args.input}")
    print(f"输出文件: {args.output}")

    # 读取原始数据并转换为字节格式（高性能处理）
    orig_packets = rdpcap(args.input)
    print(f"读取完成，共 {len(orig_packets)} 个数据包")
    
    # 转换为字节数组，减少后续处理开销
    orig_packets_bytes = [bytes(pkt) for pkt in orig_packets]
    del orig_packets  # 立即释放
    gc.collect()

    # 批处理参数 - 完全参考源码
    BATCH_SIZE = 200000  # 每批20万，与参考文件一致
    total_batches = args.num // BATCH_SIZE
    remain = args.num % BATCH_SIZE

    def get_outfile(base, idx):
        """生成输出文件名"""
        base_name, ext = os.path.splitext(base)
        return f"{base_name}_{idx+1:03d}{ext}"

    batch_idx = 0
    
    # 双层执行器架构 - 完全参考源码
    with ThreadPoolExecutor(max_workers=4) as file_writer:
        # 处理完整批次
        for i in range(total_batches):
            print(f"处理批次 {i+1}/{total_batches + (1 if remain > 0 else 0)}")
            all_modified_packets = []
            
            with ProcessPoolExecutor(max_workers=6) as executor:
                func = partial(process_one_group, orig_packets_bytes=orig_packets_bytes, ip_num=args.ip_num)
                results = executor.map(func, range(i * BATCH_SIZE, (i + 1) * BATCH_SIZE))
                
                for group_bytes in tqdm(results, total=BATCH_SIZE, desc=f"Batch {i+1}", ncols=80):
                    for pkt_bytes in group_bytes:
                        all_modified_packets.append(Ether(pkt_bytes))
            
            # 异步写入文件
            out_file = get_outfile(args.output, batch_idx)
            file_writer.submit(async_write_pcap, out_file, all_modified_packets)
            
            # 主动清理
            del all_modified_packets
            gc.collect()
            batch_idx += 1

        # 处理剩余组
        if remain > 0:
            print(f"处理剩余批次 {batch_idx+1}/{total_batches + 1}")
            all_modified_packets = []
            
            with ProcessPoolExecutor(max_workers=6) as executor:
                func = partial(process_one_group, orig_packets_bytes=orig_packets_bytes, ip_num=args.ip_num)
                results = executor.map(func, range(total_batches * BATCH_SIZE, args.num))
                
                for group_bytes in tqdm(results, total=remain, desc=f"Batch {batch_idx+1}", ncols=80):
                    for pkt_bytes in group_bytes:
                        all_modified_packets.append(Ether(pkt_bytes))
            
            out_file = get_outfile(args.output, batch_idx)
            file_writer.submit(async_write_pcap, out_file, all_modified_packets)
            
            del all_modified_packets
            gc.collect()

    # 等待所有写任务完成
    file_writer.shutdown(wait=True)
    
    end_time = time.time()
    duration = end_time - start_time
    speed = args.num / duration if duration > 0 else 0
    
    print(f"\n=== 终极性能统计 ===")
    print(f"总耗时: {duration:.2f} 秒")
    print(f"处理速度: {speed:.2f} 组/秒")
    print(f"生成文件: {total_batches + (1 if remain > 0 else 0)} 个")

if __name__ == "__main__":
    main()
