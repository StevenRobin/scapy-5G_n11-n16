from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
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

def modify_json_data(payload, modifications):
    """修改JSON数据中的目标字段"""
    try:
        # 跳过空数据段
        if not payload.strip():
            print("[跳过空数据段]")
            return None

        data = json.loads(payload)
        modified = False

        def recursive_modify(obj, modifications):
            """递归修改嵌套JSON对象"""
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in modifications:
                        print(f"[+] 修改JSON字段 {key}: {value} -> {modifications[key]}")
                        obj[key] = modifications[key]
                        modified = True
                    elif isinstance(value, (dict, list)):
                        recursive_modify(value, modifications)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        recursive_modify(item, modifications)

        recursive_modify(data, modifications)
        return json.dumps(data, indent=None).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def process_http2_data_frame(frame_data, modifications):
    """处理HTTP/2 DATA帧中的多部分数据"""
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    json_part = parts[i + 1].split(b"\r\n\r\n", 1)[1]
                    modified = modify_json_data(json_part, modifications)
                    if modified:
                        parts[i + 1] = parts[i + 1].split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n" + modified
        return b''.join(parts)
    else:
        return modify_json_data(frame_data, modifications)

def process_packet(pkt, modifications, last_seq):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset + 9 <= len(raw):
            # 解析帧头
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            # 跳过空帧数据段
            if frame_len == 0:
                print("[跳过空HTTP/2帧]")
                offset = frame_end
                continue

            # 处理DATA帧（类型0x0）
            if frame_type == 0x0:
                modified_frame_data = process_http2_data_frame(frame_data, modifications)
                if modified_frame_data:
                    frame_len = len(modified_frame_data)
                    frame_header.length = frame_len
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    continue

            # 保留未修改的帧
            new_payload += raw[offset:frame_end]
            offset = frame_end

        # 更新原始载荷
        if new_payload:
            pkt[Raw].load = new_payload

        # 更新IP和TCP长度
        pkt[IP].len = len(pkt[IP])  # 重新计算IP长度
        pkt[TCP].len = len(pkt[TCP]) + len(pkt[Raw].load)  # 重新计算TCP长度
        pkt[IP].chksum = None       # 删除IP校验和以便自动重新计算
        pkt[TCP].chksum = None      # 删除TCP校验和以便自动重新计算

        # 更新TCP序列号
        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        if flow in last_seq:
            pkt[TCP].seq = last_seq[flow]
        last_seq[flow] = pkt[TCP].seq + len(pkt[Raw].load)

        # 更新帧长度
        pkt.wirelen = len(pkt)  # 捕获到的帧总长度
        pkt.caplen = pkt.wirelen  # 捕获到的有效数据长度

# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"  # 替换为您的PCAP文件路径
PCAP_OUT = "pcap/N16_modified113.pcap"   # 替换为输出PCAP文件路径

# JSON字段修改内容
MODIFICATIONS = {
    "supi": "imsi-460012300000001",
    "pei": "imeisv-8611101000000011",
    "gpsi": "msisdn-8613900000001",
    "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
    "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "50000001"},
    "ueIpv4Address": "100.0.0.1",
    "nrCellId": "010000001"
}

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified_packets = []

# 保存每个流的最后TCP序列号
last_seq = {}

for pkt in packets:
    if TCP in pkt and Raw in pkt:
        process_packet(pkt, MODIFICATIONS, last_seq)
    modified_packets.append(pkt)

print(f"保存修改后的PCAP到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)