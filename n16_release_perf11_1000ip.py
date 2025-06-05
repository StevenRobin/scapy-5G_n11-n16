#!/usr/bin/env python3
"""
N16接口数据包批量处理工具 - 高性能版本
功能：批量修改PCAP文件中的IP地址、端口和HTTP/2头部信息
支持IP地址循环和高并发处理
"""

from scapy.all import rdpcap, wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from hpack import Decoder, Encoder
import os
import gc
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import partial
import argparse
import time
import copy
import struct
from tqdm import tqdm

# ============================================================================
# 全局变量定义
# ============================================================================

# IP地址替换映射
IP_REPLACEMENTS = {}

# 增量函数定义
def inc_ip(ip_str, i):
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

def inc_int(s, i):
    return str(int(s) + i)

# ============================================================================
# 核心数据包处理函数
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
# HTTP/2数据处理 - 零拷贝优化
# ============================================================================

def update_global_vars(i, ip_num=1000):
    """更新全局变量，为每个组生成对应的参数"""
    global IP_REPLACEMENTS
    
    # 基础配置
    base = {
        "ismfId1": "10000000",
        "pduSessionId1": "10000001",
        "sip1": "30.0.0.1",
        "dip1": "40.0.0.1"
    }
    
    # 生成递增的参数
    ismfId1 = inc_int(base["ismfId1"], i)
    pduSessionId1 = inc_int(base["pduSessionId1"], i)
    sip1 = inc_ip(base["sip1"], i % ip_num)
    dip1 = inc_ip(base["dip1"], i % ip_num)
    sport1 = 10001 + ((i // ip_num) % 50000)
    
    # 更新全局映射
    IP_REPLACEMENTS = {
        "200.20.20.26": sip1,
        "200.20.20.25": dip1
    }
    
    return sip1, dip1, sport1, ismfId1, pduSessionId1

def process_http2_payload_simple(pkt_idx, raw_payload, dip2, pduSessionId2, decoder, verbose=False):
    """处理HTTP/2 payload，修改HEADERS帧"""
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
    
    try:
        # 使用现有decoder状态解码
        headers = list(decoder.decode(target_frame['payload']))
        
        modified_headers = modify_headers_hpack(headers, dip2, pduSessionId2, pkt_idx)
        
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
        if verbose:
            print(f"[ERROR] pkt{pkt_idx} HPACK decode/encode failed: {e}")
        return raw_payload

def modify_headers_hpack(headers, dip2, pduSessionId2, pkt_idx=None):
    """修改HTTP/2头部中的:authority和:path字段"""
    new_headers = []
    for name, value in headers:
        if pkt_idx in (9, 13):
            if isinstance(name, str):
                name = name.encode('utf-8')
            if isinstance(value, str):
                value = value.encode('utf-8')
        
        # authority严格替换
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

# ============================================================================
# 核心数据包处理函数
# ============================================================================

def process_one_group_ultra_performance(orig_packets_bytes, group_id, ip_num=1000):
    """单组数据包处理函数 - 已修复IP循环功能"""    # 更新全局变量，传递ip_num参数
    sip1, dip1, sport1, ismfId1, pduSessionId1 = update_global_vars(group_id, ip_num)
      # 反序列化数据包
    orig_packets = [Ether(pkt_bytes) for pkt_bytes in orig_packets_bytes]
    
    # 使用正确的IP地址和参数
    sip2 = sip1
    dip2 = dip1  
    sport2 = sport1
    pduSessionId2 = int(pduSessionId1)
    
    # 处理流程
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
                except Exception:
                    pass  # 忽略HPACK状态更新失败
    
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
                    pkt_idx, new_pkt[Raw].load, dip2, pduSessionId2, decoder, verbose=False
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
    
    return [bytes(pkt) for pkt in output_packets]

# ============================================================================
# 辅助函数
# ============================================================================

def process_one_group(i, orig_packets_bytes, ip_num=1000):
    """高性能单组处理函数"""
    return process_one_group_ultra_performance(orig_packets_bytes, i, ip_num)

def async_write_pcap(file_path, packets_list):
    """异步写入PCAP文件"""
    try:
        wrpcap(file_path, packets_list)
        return file_path
    except Exception as e:
        print(f"写入文件失败 {file_path}: {e}")
        return None

# ============================================================================
# 主函数
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="N16接口数据包批量处理工具")
    parser.add_argument("-i", "--input", default="pcap/N16_release_18p.pcap", help="输入pcap文件路径")
    parser.add_argument("-o", "--output", default="pcap/N16_relese_5k.pcap", help="输出PCAP文件路径")
    parser.add_argument("-n", "--num", type=int, default=5000, help="循环生成报文组数")
    parser.add_argument("--ip-num", type=int, default=1000, help="IP循环数量")
    args = parser.parse_args()

    start_time = time.time()
    print(f"开始处理: {args.num} 个文件组")
    print(f"输入文件: {args.input}")
    print(f"输出文件: {args.output}")

    # 读取原始数据并转换为字节格式
    orig_packets = rdpcap(args.input)
    print(f"读取完成，共 {len(orig_packets)} 个数据包")
    
    # 转换为字节数组，减少后续处理开销
    orig_packets_bytes = [bytes(pkt) for pkt in orig_packets]
    del orig_packets
    gc.collect()    # 批处理参数
    BATCH_SIZE = 200000  # 每批20万
    total_batches = args.num // BATCH_SIZE
    remain = args.num % BATCH_SIZE

    def get_outfile(base, idx):
        """生成输出文件名"""
        base_name, ext = os.path.splitext(base)
        return f"{base_name}_{idx+1:03d}{ext}"

    batch_idx = 0
    
    # 双层执行器架构
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
            gc.collect()    # 等待所有写任务完成
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
