from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re

# 自定义 HTTP/2 帧头解析
class HTTP2FrameHeader(Packet):
    name = "HTTP2FrameHeader"
    fields_desc = [
        BitField("length", 0, 24),
        ByteField("type", 0),
        ByteField("flags", 0),
        BitField("reserved", 0, 1),
        BitField("stream_id", 0, 31)
    ]

def process_http2_frame_header(raw, offset):
    """解析 HTTP/2 帧头部，并防止对超出数据范围的读取"""
    try:
        if offset + 9 > len(raw):
            return None, None, None, None, len(raw)
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        # 当帧体长度超过剩余捕获数据时，使用剩余长度
        frame_end = offset + 9 + frame_len
        if frame_end > len(raw):
            print("[警告] 帧长度超过捕获长度，调整为剩余数据长度")
            frame_end = len(raw)
            frame_len = frame_end - (offset + 9)
            frame_header.length = frame_len
        frame_data = raw[offset + 9:frame_end]
        return frame_header, frame_len, frame_type, frame_data, frame_end
    except Exception as e:
        print(f"帧解析错误: {str(e)}")
        return None, None, None, None, len(raw)

def process_http2_data_frame(frame_data, modifications):
    """处理 HTTP/2 数据帧中的 JSON 数据"""
    try:
        decoder = Decoder()
        decoded_headers = dict(decoder.decode(frame_data))
        # 遍历并修改内容
        if "content-length" in decoded_headers:
            print(f"[+] 原始 content-length: {decoded_headers['content-length']}")
            decoded_headers["content-length"] = str(modifications)
            print(f"[+] 修改后 content-length: {decoded_headers['content-length']}")
        encoder = Encoder()
        return encoder.encode(decoded_headers.items())
    except Exception as e:
        print(f"[HTTP/2 数据帧解析错误] {str(e)}")
        return frame_data

def modify_content_length(packet_index, frame_header, target_lengths):
    """根据给定的报文索引，修改 content-length 字段"""
    if packet_index in target_lengths:
        print(f"[+] 修改第 {packet_index} 个报文的 content-length 为 {target_lengths[packet_index]}")
        frame_header.length = target_lengths[packet_index]

def process_packet(pkt, modifications, seq_diff, ip_replacements, target_lengths, packet_index):
    """
    对 TCP 包内部的 HTTP/2 数据帧进行处理：
    1. 解析所有 HTTP/2 帧，对 DATA 帧进行 JSON 数据修改。
    2. 修改五元组 IP 地址对。
    3. 修改指定的 content-length。
    4. 根据包内负载变化计算偏移量，累加调整 TCP 序号。
    5. 删除校验和字段，让 Scapy 自动重新生成。
    """
    if pkt.haslayer(IP):
        # 修改五元组 IP 地址对
        if pkt[IP].src in ip_replacements:
            print(f"[+] 替换源IP {pkt[IP].src} -> {ip_replacements[pkt[IP].src]}")
            pkt[IP].src = ip_replacements[pkt[IP].src]
        if pkt[IP].dst in ip_replacements:
            print(f"[+] 替换目的IP {pkt[IP].dst} -> {ip_replacements[pkt[IP].dst]}")
            pkt[IP].dst = ip_replacements[pkt[IP].dst]

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset < len(raw):
            # 如果剩余数据不足 9 个字节，则直接追加剩余数据
            if offset + 9 > len(raw):
                new_payload += raw[offset:]
                offset = len(raw)
                break

            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if frame_header is None:
                break

            # 修改 content-length 字段
            modify_content_length(packet_index, frame_header, target_lengths)

            # 处理 DATA 帧（类型为 0x0）
            if frame_type == 0x0:
                modified_frame_data = process_http2_data_frame(frame_data, target_lengths.get(packet_index, frame_len))
                if modified_frame_data:
                    frame_len = len(modified_frame_data)
                    frame_header.length = frame_len
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    continue

            # 保留未修改的帧
            new_payload += raw[offset:frame_end]
            offset = frame_end

        # 若载荷被修改，则计算长度差
        original_length = len(raw)
        new_length = len(new_payload)
        diff = new_length - original_length

        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        if flow not in seq_diff:
            seq_diff[flow] = 0
        # 调整数值：原始序号加上累计偏移量
        pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
        # 更新累计偏移量
        seq_diff[flow] += diff

        pkt[Raw].load = new_payload

        # 删除校验和与长度字段，让 Scapy 自动重算
        if hasattr(pkt[IP], 'chksum'):
            del pkt[IP].chksum
        if hasattr(pkt[TCP], 'chksum'):
            del pkt[TCP].chksum
        if hasattr(pkt[IP], 'len'):
            del pkt[IP].len

        # 更新帧长度
        pkt.wirelen = len(pkt)  # 捕获到的帧总长度
        pkt.caplen = pkt.wirelen  # 捕获到的有效数据长度

# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"   # 输入 PCAP 文件路径
PCAP_OUT = "pcap/N16_modified136.pcap"   # 输出 PCAP 文件路径

# JSON 字段修改内容
MODIFICATIONS = {
    "supi": "imsi-460012300000001",
    "pei": "imeisv-8611101000000011",
    "gpsi": "msisdn-8613900000001",
    "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
    "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "50000001"},
    "ueIpv4Address": "100.0.0.1",
    "nrCellId": "010000001",
    "ismfPduSessionUri": "http://200.20.20.26:8080/nsmf-pdusession/v1/pdu-sessions/10000001"  # Updated ID
}

# 五元组 IP 替换内容
IP_REPLACEMENTS = {
    "200.20.20.26": "30.0.0.1",
    "200.20.20.25": "40.0.0.1"
}

# 指定的 content-length 修改目标
TARGET_LENGTHS = {
    11: 375,
    13: 771,
    15: 379
}

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified_packets = []

# 保存每个流累计的 TCP 序号偏移量
seq_diff = {}

for index, pkt in enumerate(packets, start=1):
    if TCP in pkt or Raw in pkt:
        process_packet(pkt, MODIFICATIONS, seq_diff, IP_REPLACEMENTS, TARGET_LENGTHS, index)
    modified_packets.append(pkt)

print(f"保存修改后的 PCAP 到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)