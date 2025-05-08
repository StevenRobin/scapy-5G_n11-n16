from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder
import json
import re

# 自定义HTTP/2帧头解析
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
    """解析HTTP/2帧头部"""
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

def extract_json_data(payload):
    """提取并打印JSON数据中的键值对"""
    try:
        # 跳过空数据
        if not payload.strip():
            print("跳过空数据段")
            return

        # 尝试解码为JSON
        data = json.loads(payload)
        print("提取的JSON数据:")
        for key, value in data.items():
            print(f"{key}: {value}")
    except json.JSONDecodeError as e:
        print(f"JSON处理错误: {str(e)}")
        print(f"原始数据段: {payload[:100]}...")  # 打印前100字符以便调试
    except Exception as e:
        print(f"其他处理错误: {str(e)}")
        print(f"原始数据段: {payload[:100]}...")  # 打印前100字符以便调试

def process_http2_data_frame(frame_data):
    """处理HTTP/2 DATA帧中的多部分数据"""
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    json_part = parts[i + 1].split(b"\r\n\r\n", 1)[1]
                    extract_json_data(json_part)
    else:
        extract_json_data(frame_data)

def process_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0

        while offset + 9 <= len(raw):
            # 解析帧头
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            # 处理DATA帧（类型0x0）
            if frame_type == 0x0:
                process_http2_data_frame(frame_data)

            # 跳到下一个帧的偏移量
            offset = frame_end

# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"  # 替换为您的PCAP文件路径

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)

for pkt in packets:
    if TCP in pkt and Raw in pkt:
        process_packet(pkt)
