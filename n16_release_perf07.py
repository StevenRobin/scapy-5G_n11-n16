#!/usr/bin/env python3
"""
性能优化版本：基于功能正确的 n16_release_mod03_funcOK.py 进行性能优化
主要优化：
1. IP地址递增算法优化（整数运算）
2. HTTP/2帧解析优化（位运算）
3. 内存管理和定期清理
4. 批量预计算和缓存
5. 多进程处理优化
"""

from scapy.all import rdpcap, wrpcap, IP, TCP, Raw
from hpack import Decoder, Encoder
import copy
import re
import argparse
import struct
import os
import time
import gc
import psutil
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from functools import partial
import multiprocessing as mp
from contextlib import contextmanager

class MemoryManager:
    """内存管理器，用于监控和控制内存使用"""
    
    def __init__(self, max_memory_mb=2048):
        self.max_memory_mb = max_memory_mb
        self.cleanup_counter = 0
        
    def get_memory_usage(self):
        """获取当前内存使用情况（MB）"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            return memory_info.rss / 1024 / 1024  # MB
        except:
            return 0.0
    
    def check_memory(self):
        """检查内存使用是否超限"""
        current_memory = self.get_memory_usage()
        return current_memory, current_memory > self.max_memory_mb
    
    def force_cleanup(self):
        """强制内存清理"""
        gc.collect()
        self.cleanup_counter += 1
        
    @contextmanager
    def memory_cleanup(self):
        """内存清理上下文管理器"""
        try:
            yield self
        finally:
            self.force_cleanup()

class OptimizedIPIncrementer:
    """优化的IP地址递增器，使用整数运算避免字符串操作"""
    
    def __init__(self, base_ip):
        parts = list(map(int, base_ip.split('.')))
        self.base_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        
    def get_ip(self, offset):
        """快速获取偏移后的IP地址"""
        ip_int = self.base_int + offset
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

def parse_http2_frame(data, offset=0):
    """严格按照HTTP/2规范解析帧"""
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


def parse_http2_frame_optimized(data, offset=0):
    """优化的HTTP/2帧解析，使用位运算提升性能"""
    if offset + 9 > len(data):
        return None
    
    # 使用位运算快速解析帧头，避免struct.unpack
    length = (data[offset] << 16) | (data[offset+1] << 8) | data[offset+2]
    frame_type = data[offset+3]
    flags = data[offset+4]
    stream_id = ((data[offset+5] << 24) | (data[offset+6] << 16) | 
                (data[offset+7] << 8) | data[offset+8]) & 0x7FFFFFFF
    
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
    """重建HTTP/2帧，严格保证长度字段与payload一致"""
    length = len(payload)
    header = struct.pack('!I', length)[1:]  # 取后3字节作为长度
    header += struct.pack('!B', frame_type)
    header += struct.pack('!B', flags)
    header += struct.pack('!I', stream_id & 0x7FFFFFFF)
    return header + payload


def rebuild_http2_frame_optimized(frame_type, flags, stream_id, payload):
    """优化的HTTP/2帧重建，使用位运算避免struct.pack"""
    length = len(payload)
    # 使用位运算构建帧头，避免struct.pack
    header = bytearray(9)
    header[0] = (length >> 16) & 0xFF
    header[1] = (length >> 8) & 0xFF
    header[2] = length & 0xFF
    header[3] = frame_type
    header[4] = flags
    header[5] = (stream_id >> 24) & 0xFF
    header[6] = (stream_id >> 16) & 0xFF
    header[7] = (stream_id >> 8) & 0xFF
    header[8] = stream_id & 0xFF
    
    return bytes(header) + payload


def modify_headers_hpack(headers, dip2, pduSessionId2, pkt_idx=None):
    """严格替换:authority和:path，其他头部顺序和内容全部保留，不去重"""
    new_headers = []
    for name, value in headers:
        if pkt_idx in (9, 13):
            if isinstance(name, str):
                name = name.encode('utf-8')
            if isinstance(value, str):
                value = value.encode('utf-8')        # authority严格替换
        if name == b':authority' and pkt_idx in (9, 13):
            new_headers.append((name, dip2.encode('utf-8')))
        # path严格替换
        elif name == b':path' and pkt_idx == 9:
            new_headers.append((name, f"/nsmf-pdusession/v1/pdu-sessions/{pduSessionId2}/modify".encode('utf-8')))
        elif name == b':path' and pkt_idx == 13:
            new_headers.append((name, f"/nsmf-pdusession/v1/pdu-sessions/{pduSessionId2}".encode('utf-8')))
        else:
            new_headers.append((name, value))
    return new_headers


def modify_headers_hpack_optimized(headers, dip2_bytes, pdusession_path_9, pdusession_path_13, pkt_idx):
    """优化的头部修改函数，预编码常用值避免重复编码"""
    new_headers = []
    authority_key = b':authority'
    path_key = b':path'
    
    for name, value in headers:
        if pkt_idx in (9, 13):
            if isinstance(name, str):
                name = name.encode('utf-8')
            if isinstance(value, str):
                value = value.encode('utf-8')
                
        if name == authority_key and pkt_idx in (9, 13):
            new_headers.append((name, dip2_bytes))
        elif name == path_key and pkt_idx == 9:
            new_headers.append((name, pdusession_path_9))
        elif name == path_key and pkt_idx == 13:
            new_headers.append((name, pdusession_path_13))
        else:
            new_headers.append((name, value))
    return new_headers


def process_http2_payload_simple(pkt_idx, raw_payload, dip2, pduSessionId2, decoder, verbose=False):
    """使用已建立状态的decoder处理HEADERS帧，保证头部完整"""
    if raw_payload.startswith(b'PRI * HTTP/2.0'):
        return raw_payload
    
    if not decoder:
        if verbose:
            print(f"[ERROR] pkt{pkt_idx} no decoder available")
        return raw_payload
        
    frames = []
    offset = 0
    while offset < len(raw_payload):
        frame = parse_http2_frame(raw_payload, offset)
        if not frame:
            break
        frames.append(frame)
        offset = frame['end_offset']
    
    # 找到第一个HEADERS帧
    headers_idx = None
    for i, f in enumerate(frames):
        if f['type'] == 1:  # HEADERS
            headers_idx = i
            break
    if headers_idx is None:
        return raw_payload
        
    target_frame = frames[headers_idx]
    
    try:        # 使用现有decoder状态解码
        headers = list(decoder.decode(target_frame['payload']))
        if pkt_idx == 13:
            print(f"[DEBUG] pkt13 decoded headers:")
            for name, value in headers:
                print(f"  {name}: {value}")
            
        modified_headers = modify_headers_hpack(headers, dip2, pduSessionId2, pkt_idx)
        if pkt_idx == 13:
            print(f"[DEBUG] pkt13 modified headers:")
            for name, value in modified_headers:
                print(f"  {name}: {value}")
        encoder = Encoder()
        new_payload = encoder.encode(modified_headers)
        
        new_frame_data = rebuild_http2_frame(
            target_frame['type'],
            target_frame['flags'],
            target_frame['stream_id'],
            new_payload
        )
        
        # 重组完整payload，只替换HEADERS帧
        result_payload = b''
        for i, frame in enumerate(frames):
            if i == headers_idx:
                result_payload += new_frame_data
            else:
                result_payload += raw_payload[frame['start_offset']:frame['end_offset']]
        return result_payload
        
    except Exception as e:
        print(f"[ERROR] pkt{pkt_idx} HPACK decode/encode failed: {e}")
        return raw_payload

def process_one_group(orig_packets, sip2, dip2, sport2, pduSessionId2, verbose=False):
    output_packets = []
    flow_decoders = {}
    seq_diff = {}  # 序列号差异追踪
    
    # 第一步：为所有流创建decoder并按序处理所有包以建立正确的HPACK状态
    for pkt_idx, pkt in enumerate(orig_packets, 1):
        if pkt.haslayer(Raw) and len(pkt[Raw].load) > 0:
            original_flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            
            # 为每个流创建decoder
            if original_flow not in flow_decoders:
                flow_decoders[original_flow] = Decoder()
            
            decoder = flow_decoders[original_flow]
            raw_data = bytes(pkt[Raw].load)
            
            if not raw_data.startswith(b'PRI * HTTP/2.0'):
                try:
                    frames = []
                    offset = 0
                    while offset < len(raw_data):
                        frame = parse_http2_frame(raw_data, offset)
                        if not frame:
                            break
                        frames.append(frame)
                        offset = frame['end_offset']
                    for frame in frames:
                        if frame['type'] == 1:  # HEADERS帧
                            if pkt_idx not in [9, 13]:  # 非目标包只更新状态
                                decoder.decode(frame['payload'])
                except Exception as e:
                    if verbose:
                        print(f"[WARN] pkt{pkt_idx} HPACK state update failed: {e}")
    
    # 第二步：重新处理所有包，进行实际修改和序列号调整
    for pkt_idx, pkt in enumerate(orig_packets, 1):
        new_pkt = copy.deepcopy(pkt)
        
        # 修改IP地址和端口
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
        
        # TCP序列号处理
        if new_pkt.haslayer(TCP):
            flow = (new_pkt[IP].src, new_pkt[IP].dst, new_pkt[TCP].sport, new_pkt[TCP].dport)
            rev_flow = (new_pkt[IP].dst, new_pkt[IP].src, new_pkt[TCP].dport, new_pkt[TCP].sport)
            
            # 初始化序列号差异
            if flow not in seq_diff:
                seq_diff[flow] = 0
            if rev_flow not in seq_diff:
                seq_diff[rev_flow] = 0
            
            flags = new_pkt[TCP].flags
            is_syn = flags & 0x02 != 0
            is_fin = flags & 0x01 != 0
            is_rst = flags & 0x04 != 0
            has_payload = new_pkt.haslayer(Raw) and len(new_pkt[Raw].load) > 0
            
            original_length = len(new_pkt[Raw].load) if has_payload else 0
            
            # 处理HTTP/2 payload
            if has_payload and pkt_idx in [9, 13]:  # 只修改目标包
                original_flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                decoder = flow_decoders.get(original_flow)
                
                new_payload = process_http2_payload_simple(
                    pkt_idx, new_pkt[Raw].load, dip2, pduSessionId2, decoder, verbose
                )
                new_pkt[Raw].load = new_payload
            
            # 计算payload长度差异
            new_length = len(new_pkt[Raw].load) if has_payload else 0
            diff = new_length - original_length
            
            # TCP序列号和ACK号调整
            if has_payload and not (is_syn or is_fin or is_rst):
                # 有payload的数据包：先调整序列号，再累计差异
                new_pkt[TCP].seq = new_pkt[TCP].seq + seq_diff[flow]
                if new_pkt[TCP].flags & 0x10 and hasattr(new_pkt[TCP], 'ack'):
                    new_pkt[TCP].ack = new_pkt[TCP].ack + seq_diff[rev_flow]
                seq_diff[flow] += diff
            else:
                # SYN/FIN/RST或无payload包：只调整序列号，不累计差异
                new_pkt[TCP].seq = new_pkt[TCP].seq + seq_diff[flow]
                if new_pkt[TCP].flags & 0x10 and hasattr(new_pkt[TCP], 'ack'):
                    new_pkt[TCP].ack = new_pkt[TCP].ack + seq_diff[rev_flow]
        
        # 强制重算IP/TCP长度和校验和
        if new_pkt.haslayer(Raw) and new_pkt.haslayer(TCP) and new_pkt.haslayer(IP):
            raw_len = len(new_pkt[Raw].load)
            tcp_hdr_len = new_pkt[TCP].dataofs * 4 if hasattr(new_pkt[TCP], 'dataofs') else 20
            ip_hdr_len = new_pkt[IP].ihl * 4 if hasattr(new_pkt[IP], 'ihl') else 20

            # IP总长度 = IP头 + TCP头 + Raw
            new_pkt[IP].len = ip_hdr_len + tcp_hdr_len + raw_len
            # TCP数据偏移 = TCP头长度/4
            new_pkt[TCP].dataofs = int(tcp_hdr_len / 4)
        
        # 清空校验和让Scapy自动重算
        if new_pkt.haslayer(IP) and hasattr(new_pkt[IP], 'chksum'):
            del new_pkt[IP].chksum
        if new_pkt.haslayer(TCP) and hasattr(new_pkt[TCP], 'chksum'):
            del new_pkt[TCP].chksum
        if new_pkt.haslayer(IP) and hasattr(new_pkt[IP], 'len'):
            # 让Scapy重新计算IP长度
            pass  # 上面已经设置了正确的len
            
        # 更新wire长度
        if hasattr(new_pkt, 'wirelen'):
            new_pkt.wirelen = len(new_pkt)
        if hasattr(new_pkt, 'caplen'):
            new_pkt.caplen = len(new_pkt)
        
        output_packets.append(new_pkt)
    return output_packets


def process_one_group_optimized(orig_packets, sip2, dip2, sport2, pduSessionId2, memory_manager=None, verbose=False):
    """优化版本的单组处理函数，提升性能"""
    output_packets = []
    flow_decoders = {}
    seq_diff = {}  # 序列号差异追踪
    
    # 预编码常用字节值，避免重复编码
    dip2_bytes = dip2.encode('utf-8')
    pdusession_path_9 = f"/nsmf-pdusession/v1/pdu-sessions/{pduSessionId2}/modify".encode('utf-8')
    pdusession_path_13 = f"/nsmf-pdusession/v1/pdu-sessions/{pduSessionId2}".encode('utf-8')
    
    # 第一步：为所有流创建decoder并按序处理所有包以建立正确的HPACK状态
    for pkt_idx, pkt in enumerate(orig_packets, 1):
        if pkt.haslayer(Raw) and len(pkt[Raw].load) > 0:
            original_flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            
            # 为每个流创建decoder
            if original_flow not in flow_decoders:
                flow_decoders[original_flow] = Decoder()
            
            decoder = flow_decoders[original_flow]
            raw_data = bytes(pkt[Raw].load)
            
            if not raw_data.startswith(b'PRI * HTTP/2.0'):
                try:
                    frames = []
                    offset = 0
                    while offset < len(raw_data):
                        # 使用优化的帧解析
                        frame = parse_http2_frame_optimized(raw_data, offset)
                        if not frame:
                            break
                        frames.append(frame)
                        offset = frame['end_offset']
                    for frame in frames:
                        if frame['type'] == 1:  # HEADERS帧
                            if pkt_idx not in [9, 13]:  # 非目标包只更新状态
                                decoder.decode(frame['payload'])
                except Exception as e:
                    if verbose:
                        print(f"[WARN] pkt{pkt_idx} HPACK state update failed: {e}")
    
    # 第二步：重新处理所有包，进行实际修改和序列号调整
    for pkt_idx, pkt in enumerate(orig_packets, 1):
        new_pkt = copy.deepcopy(pkt)
        
        # 修改IP地址和端口
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
        
        # TCP序列号处理
        if new_pkt.haslayer(TCP):
            flow = (new_pkt[IP].src, new_pkt[IP].dst, new_pkt[TCP].sport, new_pkt[TCP].dport)
            rev_flow = (new_pkt[IP].dst, new_pkt[IP].src, new_pkt[TCP].dport, new_pkt[TCP].sport)
            
            # 初始化序列号差异
            if flow not in seq_diff:
                seq_diff[flow] = 0
            if rev_flow not in seq_diff:
                seq_diff[rev_flow] = 0
            
            flags = new_pkt[TCP].flags
            is_syn = flags & 0x02 != 0
            is_fin = flags & 0x01 != 0
            is_rst = flags & 0x04 != 0
            has_payload = new_pkt.haslayer(Raw) and len(new_pkt[Raw].load) > 0
            
            original_length = len(new_pkt[Raw].load) if has_payload else 0
            
            # 处理HTTP/2 payload
            if has_payload and pkt_idx in [9, 13]:  # 只修改目标包
                original_flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                decoder = flow_decoders.get(original_flow)
                
                # 使用优化的payload处理
                new_payload = process_http2_payload_optimized(
                    pkt_idx, new_pkt[Raw].load, dip2_bytes, pdusession_path_9, 
                    pdusession_path_13, decoder, verbose
                )
                new_pkt[Raw].load = new_payload
            
            # 计算payload长度差异
            new_length = len(new_pkt[Raw].load) if has_payload else 0
            diff = new_length - original_length
            
            # TCP序列号和ACK号调整
            if has_payload and not (is_syn or is_fin or is_rst):
                # 有payload的数据包：先调整序列号，再累计差异
                new_pkt[TCP].seq = new_pkt[TCP].seq + seq_diff[flow]
                if new_pkt[TCP].flags & 0x10 and hasattr(new_pkt[TCP], 'ack'):
                    new_pkt[TCP].ack = new_pkt[TCP].ack + seq_diff[rev_flow]
                seq_diff[flow] += diff
            else:
                # SYN/FIN/RST或无payload包：只调整序列号，不累计差异
                new_pkt[TCP].seq = new_pkt[TCP].seq + seq_diff[flow]
                if new_pkt[TCP].flags & 0x10 and hasattr(new_pkt[TCP], 'ack'):
                    new_pkt[TCP].ack = new_pkt[TCP].ack + seq_diff[rev_flow]
        
        # 强制重算IP/TCP长度和校验和
        if new_pkt.haslayer(Raw) and new_pkt.haslayer(TCP) and new_pkt.haslayer(IP):
            raw_len = len(new_pkt[Raw].load)
            tcp_hdr_len = new_pkt[TCP].dataofs * 4 if hasattr(new_pkt[TCP], 'dataofs') else 20
            ip_hdr_len = new_pkt[IP].ihl * 4 if hasattr(new_pkt[IP], 'ihl') else 20

            # IP总长度 = IP头 + TCP头 + Raw
            new_pkt[IP].len = ip_hdr_len + tcp_hdr_len + raw_len
            # TCP数据偏移 = TCP头长度/4
            new_pkt[TCP].dataofs = int(tcp_hdr_len / 4)
        
        # 清空校验和让Scapy自动重算
        if new_pkt.haslayer(IP) and hasattr(new_pkt[IP], 'chksum'):
            del new_pkt[IP].chksum
        if new_pkt.haslayer(TCP) and hasattr(new_pkt[TCP], 'chksum'):
            del new_pkt[TCP].chksum
            
        # 更新wire长度
        if hasattr(new_pkt, 'wirelen'):
            new_pkt.wirelen = len(new_pkt)
        if hasattr(new_pkt, 'caplen'):
            new_pkt.caplen = len(new_pkt)
        
        output_packets.append(new_pkt)
    
    # 内存清理
    if memory_manager:
        memory_manager.force_cleanup()
    
    return output_packets


def process_http2_payload_optimized(pkt_idx, raw_payload, dip2_bytes, pdusession_path_9, 
                                  pdusession_path_13, decoder, verbose=False):
    """优化的HTTP/2载荷处理函数，使用预编码值和优化的帧解析"""
    if raw_payload.startswith(b'PRI * HTTP/2.0'):
        return raw_payload
    
    if not decoder:
        if verbose:
            print(f"[ERROR] pkt{pkt_idx} no decoder available")
        return raw_payload
        
    frames = []
    offset = 0
    while offset < len(raw_payload):
        # 使用优化的帧解析
        frame = parse_http2_frame_optimized(raw_payload, offset)
        if not frame:
            break
        frames.append(frame)
        offset = frame['end_offset']
    
    # 找到第一个HEADERS帧
    headers_idx = None
    for i, f in enumerate(frames):
        if f['type'] == 1:  # HEADERS
            headers_idx = i
            break
    if headers_idx is None:
        return raw_payload
        
    target_frame = frames[headers_idx]
    
    try:        
        # 使用现有decoder状态解码
        headers = list(decoder.decode(target_frame['payload']))
        if pkt_idx == 13 and verbose:
            print(f"[DEBUG] pkt13 decoded headers:")
            for name, value in headers:
                print(f"  {name}: {value}")
            
        # 使用优化的头部修改，传入预编码值
        modified_headers = modify_headers_hpack_optimized(
            headers, dip2_bytes, pdusession_path_9, pdusession_path_13, pkt_idx
        )
        
        if pkt_idx == 13 and verbose:
            print(f"[DEBUG] pkt13 modified headers:")
            for name, value in modified_headers:
                print(f"  {name}: {value}")
        
        encoder = Encoder()
        new_payload = encoder.encode(modified_headers)
        
        # 使用优化的帧重建
        new_frame_data = rebuild_http2_frame_optimized(
            target_frame['type'],
            target_frame['flags'],
            target_frame['stream_id'],
            new_payload
        )
        
        # 重组完整payload，只替换HEADERS帧
        result_payload = b''
        for i, frame in enumerate(frames):
            if i == headers_idx:
                result_payload += new_frame_data
            else:
                result_payload += raw_payload[frame['start_offset']:frame['end_offset']]
        return result_payload
        
    except Exception as e:
        if verbose:
            print(f"[ERROR] pkt{pkt_idx} HPACK decode/encode failed: {e}")
        return raw_payload


def process_batch_worker(args):
    """批量处理工作函数（用于多进程）"""
    batch_start, batch_size, orig_packets, sip2_base, dip2_base, sport2_base, pduid_base, output_dir = args
    
    results = []
    for i in range(batch_size):
        group_id = batch_start + i
        sip2 = inc_ip(sip2_base, group_id)
        dip2 = inc_ip(dip2_base, group_id)
        sport2 = sport2_base + group_id
        pduSessionId2 = pduid_base + group_id
        
        # 处理数据包组
        out_packets = process_one_group(orig_packets, sip2, dip2, sport2, pduSessionId2, verbose=False)
        
        # 生成输出文件名
        output_file = os.path.join(output_dir, f"N16_batch_{group_id+1:06d}.pcap")
        
        # 保存文件
        wrpcap(output_file, out_packets)
        results.append(output_file)
        
        # 内存管理
        if i % 100 == 0:
            gc.collect()
    
    return results

def process_batch_worker_optimized(args):
    """优化版本的批量处理工作函数（用于多进程）"""
    batch_start, batch_size, orig_packets, sip2_base, dip2_base, sport2_base, pduid_base, output_dir = args
    
    # 创建内存管理器和IP递增器
    memory_manager = MemoryManager(max_memory_mb=1024)
    ip_incrementer_sip = OptimizedIPIncrementer(sip2_base)
    ip_incrementer_dip = OptimizedIPIncrementer(dip2_base)
    
    results = []
    for i in range(batch_size):
        group_id = batch_start + i
        
        # 使用优化的IP递增器
        sip2 = ip_incrementer_sip.get_ip(group_id)
        dip2 = ip_incrementer_dip.get_ip(group_id)
        sport2 = sport2_base + group_id
        pduSessionId2 = pduid_base + group_id
        
        # 使用优化版本的处理函数
        with memory_manager.memory_cleanup():
            out_packets = process_one_group_optimized(
                orig_packets, sip2, dip2, sport2, pduSessionId2, 
                memory_manager=memory_manager, verbose=False
            )
        
        # 生成输出文件名
        output_file = os.path.join(output_dir, f"N16_batch_{group_id+1:06d}.pcap")
        
        # 保存文件
        wrpcap(output_file, out_packets)
        results.append(output_file)
        
        # 定期内存清理和监控
        if i % 50 == 0:  # 比原版更频繁的清理
            current_memory, over_limit = memory_manager.check_memory()
            if over_limit:
                print(f"[WARNING] 批次 {batch_start}-{batch_start+i}: 内存使用 {current_memory:.2f} MB 超限")
            memory_manager.force_cleanup()
    
    return results

def get_memory_usage():
    """获取当前内存使用情况"""
    try:
        process = psutil.Process()
        memory_info = process.memory_info()
        return memory_info.rss / 1024 / 1024  # MB
    except:
        return 0.0

def inc_ip(base_ip, offset):
    """简单的IP地址递增函数（兼容性）"""
    parts = list(map(int, base_ip.split('.')))
    parts[3] += offset
    
    # 处理进位
    for i in range(3, 0, -1):
        if parts[i] > 255:
            parts[i-1] += parts[i] // 256
            parts[i] = parts[i] % 256
    
    return '.'.join(map(str, parts))

def main():
    parser = argparse.ArgumentParser(description="高性能批量修改PCAP中的HTTP/2 authority/path字段")
    parser.add_argument("-i", "--input", default="pcap/N16_release_18p.pcap", help="输入pcap文件路径")
    parser.add_argument("-o", "--output", default="pcap/", help="输出目录")
    parser.add_argument("-n", "--num", type=int, default=1, help="循环生成报文组数")
    parser.add_argument("--sip2", default="50.0.0.1", help="客户端起始IP")
    parser.add_argument("--dip2", default="60.0.0.1", help="服务端起始IP")
    parser.add_argument("--sport", type=int, default=20000, help="客户端起始端口")
    parser.add_argument("--pduid", type=int, default=10000001, help="pduSessionId2起始值")
    parser.add_argument("--batch-size", type=int, default=100, help="每个进程处理的批次大小")
    parser.add_argument("--workers", type=int, default=None, help="工作进程数（默认为CPU核心数）")
    parser.add_argument("--optimized", action="store_true", help="使用优化版本（IP递增器+内存管理+位运算优化）")
    parser.add_argument("--verbose", action="store_true", help="显示详细输出")
    args = parser.parse_args()

    # 创建输出目录
    os.makedirs(args.output, exist_ok=True)
      # 记录开始时间和内存使用
    start_time = time.time()
    start_memory = get_memory_usage()
    
    print(f"开始批量处理: {args.num} 个文件组")
    print(f"输入文件: {args.input}")
    print(f"输出目录: {args.output}")
    print(f"批次大小: {args.batch_size}")
    print(f"处理模式: {'优化版本' if args.optimized else '标准版本'}")
    print(f"起始内存使用: {start_memory:.2f} MB")
      # 读取原始数据包
    print("正在读取原始PCAP文件...")
    orig_packets = rdpcap(args.input)
    print(f"读取完成，共 {len(orig_packets)} 个数据包")
    
    if args.num == 1:
        # 单文件处理模式
        print("单文件处理模式")
        sip2 = args.sip2
        dip2 = args.dip2
        sport2 = args.sport
        pduSessionId2 = args.pduid
        
        if args.optimized:
            print("使用优化版本进行处理...")
            memory_manager = MemoryManager()
            with memory_manager.memory_cleanup():
                out_packets = process_one_group_optimized(
                    orig_packets, sip2, dip2, sport2, pduSessionId2, 
                    memory_manager=memory_manager, verbose=args.verbose
                )
        else:
            print("使用标准版本进行处理...")
            out_packets = process_one_group(orig_packets, sip2, dip2, sport2, pduSessionId2, args.verbose)
        
        output_file = os.path.join(args.output, "N16_release_mod2002.pcap")
        wrpcap(output_file, out_packets)
        print(f"输出文件: {output_file}")
        
    else:
        # 批量处理模式        print(f"批量处理模式: {args.num} 个文件")
        
        # 确定工作进程数
        if args.workers is None:
            args.workers = min(mp.cpu_count(), 8)  # 最多8个进程
        
        print(f"使用 {args.workers} 个工作进程")
        
        # 分批处理
        batch_args = []
        for batch_start in range(0, args.num, args.batch_size):
            batch_size = min(args.batch_size, args.num - batch_start)
            batch_args.append((
                batch_start, batch_size, orig_packets,
                args.sip2, args.dip2, args.sport, args.pduid,
                args.output
            ))
        
        print(f"分为 {len(batch_args)} 个批次处理")
        
        # 选择处理函数
        if args.optimized:
            print("使用优化版本工作函数进行批量处理...")
            worker_func = process_batch_worker_optimized
        else:
            print("使用标准版本工作函数进行批量处理...")
            worker_func = process_batch_worker
        
        # 多进程处理
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            all_results = []
            for batch_results in executor.map(worker_func, batch_args):
                all_results.extend(batch_results)
                current_memory = get_memory_usage()
                print(f"批次完成，当前内存使用: {current_memory:.2f} MB")
        
        print(f"所有批次处理完成，共生成 {len(all_results)} 个文件")
    
    # 统计结果
    end_time = time.time()
    end_memory = get_memory_usage()
    duration = end_time - start_time
    
    print(f"\n=== 处理完成 ===")
    print(f"总耗时: {duration:.2f} 秒")
    print(f"处理速度: {args.num / duration:.2f} 个文件/秒")
    print(f"结束内存使用: {end_memory:.2f} MB")
    print(f"内存变化: {end_memory - start_memory:+.2f} MB")
    
    if args.num > 1:
        print(f"输出目录: {args.output}")
        print(f"文件命名格式: N16_batch_XXXXXX.pcap")

if __name__ == "__main__":
    main()
