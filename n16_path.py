from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re

# 配置参数
TARGET_HEADERS = {
    ":path": "/nsmf-pdusession/v1/sm-contexts/1000000001/retrieve",           # 你要替换的path
    ":authority": "smf.smf"    # 你要替换的authority
}
PCAP_IN = "pcap/N16_create_16p.pcap"   # 输入 PCAP 文件路径
PCAP_OUT = "pcap/N16_modified113.pcap"   # 输出 PCAP 文件路径

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
    try:
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        frame_end = offset + 9 + frame_len
        frame_data = raw[offset + 9:frame_end]
        return frame_header, frame_len, frame_type, frame_data, frame_end
    except Exception as e:
        print(f"帧解析错误: {str(e)}")
        return None, None, None, None, None

def modify_http2_headers(frame_data, target_headers):
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        modified = False
        new_headers = []
        for name, value in headers:
            lname = name.lower()
            if lname in target_headers:
                print(f"[+] 修改Header {name}: {value} -> {target_headers[lname]}")
                new_headers.append((name, target_headers[lname]))
                modified = True
            else:
                new_headers.append((name, value))
        if modified:
            encoder = Encoder()
            new_data = encoder.encode(new_headers)
            return new_data
        return frame_data
    except Exception as e:
        print(f"HEADERS帧处理错误: {str(e)}")
        return frame_data

def process_packet(pkt, seq_diff):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''
        modified_flag = False

        while offset + 9 <= len(raw):
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            if frame_type == 0x1:  # HEADERS帧
                modified_frame_data = modify_http2_headers(frame_data, TARGET_HEADERS)
                if modified_frame_data != frame_data:
                    frame_len = len(modified_frame_data)
                    frame_header.length = frame_len
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    modified_flag = True
                    continue

            # 其他帧类型不变
            new_payload += raw[offset:frame_end]
            offset = frame_end

        if modified_flag:
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
print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified = []
seq_diff = {}

for pkt in packets:
    if TCP in pkt and Raw in pkt:
        process_packet(pkt, seq_diff)
    modified.append(pkt)

print(f"保存修改到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified)