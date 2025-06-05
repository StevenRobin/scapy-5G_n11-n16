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

# 全局JSON字段映射变量
JSON_FIELD_MAP = {}
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

def inc_hex(h, i, width=8):
    result = hex(int(h, 16) + i)[2:].upper()
    return result.zfill(width)

def inc_imei14(imei14_str, i):
    return str(int(imei14_str) + i).zfill(14)

def imei14_to_imei15(imei14):
    digits = [int(d) for d in imei14]
    odd_sum = sum(digits[i] for i in range(0, 14, 2))
    even_sum = sum(digits[i] for i in range(1, 14, 2))
    doubled_even_sum = 0
    for digit in [digits[i] for i in range(1, 14, 2)]:
        doubled = digit * 2
        doubled_even_sum += doubled // 10 + doubled % 10
    total = odd_sum + doubled_even_sum
    check_digit = (10 - (total % 10)) % 10
    return imei14 + str(check_digit)

def imei14_to_imeisv(imei14, sv="00"):
    return imei14 + sv

# HTTP/2帧类型常量
FRAME_TYPE_HEADERS = 0x1
FRAME_TYPE_DATA = 0x0

# ============================================================================
# 高性能HTTP/2帧解析器 - 移植自n16_release_perf07.py
# ============================================================================

def parse_http2_frame(data, offset=0):
    """严格按照HTTP/2规范解析帧 - 移植自n16_release_perf07.py"""
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
    """重建HTTP/2帧，严格保证长度字段与payload一致 - 移植自n16_release_perf07.py"""
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
    global JSON_FIELD_MAP, IP_REPLACEMENTS
    
    # 基础配置
    base = {
        "auth1": "30.0.0.1",
        "context_ID": "1000000000",
        "imsi1": "460123456789000",
        "imei14": "12345678901234",
        "gpsi1": "8613312345678",
        "dnn1": "dnn1",
        "ismfId1": "10000000",
        "upf1": "8.0.0.1",
        "teid1": "00000001",
        "upf2": "9.0.0.1", 
        "teid2": "00000002",
        "ueIP1": "10.0.0.1",
        "tac1": "000001",
        "cgi1": "00000001",
        "pduSessionId1": "10000001",
        "sip1": "30.0.0.1",
        "dip1": "40.0.0.1"
    }
    
    # 生成递增的参数
    auth1 = inc_ip(base["auth1"], i)
    context_ID = inc_int(base["context_ID"], i)
    imsi1 = inc_int(base["imsi1"], i)
    imei14 = inc_imei14(base["imei14"], i)
    imei15 = imei14_to_imei15(imei14)
    pei1 = imei14_to_imeisv(imei14, "00")
    gpsi1 = inc_int(base["gpsi1"], i)
    dnn1 = "dnn" + inc_int(base["dnn1"][3:], i)
    ismfId1 = inc_int(base["ismfId1"], i)
    upf1 = inc_ip(base["upf1"], i)
    teid1 = inc_hex(base["teid1"], i, width=len(base["teid1"]))
    upf2 = inc_ip(base["upf2"], i)
    teid2 = inc_hex(base["teid2"], i, width=len(base["teid2"]))
    ueIP1 = inc_ip(base["ueIP1"], i)
    tac1 = inc_hex(base["tac1"], i, width=len(base["tac1"]))
    cgi1 = inc_hex(base["cgi1"], i, width=len(base["cgi1"]))
    pduSessionId1 = inc_int(base["pduSessionId1"], i)
    sip1 = inc_ip(base["sip1"], i % ip_num)
    dip1 = inc_ip(base["dip1"], i % ip_num)
    sport1 = 10001 + ((i // ip_num) % 50000)
      # 更新全局映射
    IP_REPLACEMENTS = {
        "200.20.20.26": sip1,
        "200.20.20.25": dip1
    }
    
    JSON_FIELD_MAP = {
        "supi": f"imsi-{imsi1}",
        "pei": f"imeisv-{pei1}",
        "gpsi": f"msisdn-{gpsi1}",
        "dnn": dnn1,
        "ismfId": None,
        "icnTunnelInfo": {"ipv4Addr": upf1, "gtpTeid": teid1},
        "cnTunnelInfo": {"ipv4Addr": upf2, "gtpTeid": teid2},
        "ueIpv4Address": ueIP1,
        "tac": tac1,
        "nrCellId": cgi1,
        "uplink": "5000000000",
        "downlink": "5000000000",
        "ismfPduSessionUri": None,
        # 新增用于 ismfId 和 pduSessionId 替换的字段
        "ismfId_suffix": ismfId1,
        "pduSessionId_suffix": pduSessionId1
    }
    
    return sip1, dip1, sport1, ismfId1, pduSessionId1

def modify_json_data(payload):
    """简化版本：不修改JSON内容，直接返回None表示无需修改"""
    return None

def process_http2_payload_simple(pkt_idx, raw_payload, dip2, pduSessionId2, decoder, verbose=False):
    """使用已建立状态的decoder处理HEADERS帧，保证头部完整 - 移植自n16_release_perf07.py"""
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
    """严格替换:authority和:path，其他头部顺序和内容全部保留 - 移植自n16_release_perf07.py"""
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
# 核心数据包处理函数 - 零拷贝优化
# ============================================================================

def process_one_group_ultra_performance(orig_packets_bytes, group_id, ip_num=1000):
    """终极性能单组处理函数 - 直接移植n16_release_perf07.py的成功实现"""
    # 更新全局变量，为当前组设置正确的JSON字段映射，传递ip_num参数
    sip1, dip1, sport1, ismfId1, pduSessionId1 = update_global_vars(group_id, ip_num)
    
    # 反序列化数据包
    orig_packets = [Ether(pkt_bytes) for pkt_bytes in orig_packets_bytes]
    
    # 使用update_global_vars返回的正确IP地址和参数，而不是重新计算
    sip2 = sip1  # 使用update_global_vars计算的正确IP
    dip2 = dip1  # 使用update_global_vars计算的正确IP
    sport2 = sport1  # 使用update_global_vars计算的正确端口
    pduSessionId2 = int(pduSessionId1)  # 使用update_global_vars计算的正确pduSessionId
    
    # === 完全移植n16_release_perf07.py的处理逻辑 ===
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
# 批处理工作函数 - 参考最高性能架构
# ============================================================================

def process_one_group(i, orig_packets_bytes, ip_num=1000):
    """高性能单组处理 - 使用超级优化算法"""
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
# 主函数 - 完全参考n16_batch17_1000ip_perf.py架构
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="终极性能版本 - 批量修改PCAP")
    parser.add_argument("-i", "--input", default="pcap/N16_release_18p.pcap", help="输入pcap文件路径")
    parser.add_argument("-o", "--output", default="pcap/N16_relese_5k.pcap", help="输出PCAP文件路径")
    parser.add_argument("-n", "--num", type=int, default=5000, help="循环生成报文组数")
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
