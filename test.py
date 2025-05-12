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
        if not payload.strip():
            print("[跳过空数据段]")
            return None

        data = json.loads(payload)
        modified = False

        def recursive_modify(obj, mods):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in mods:
                        print(f"[+] 修改JSON字段 {key}: {value} -> {mods[key]}")
                        obj[key] = mods[key]
                        modified = True
                    elif isinstance(value, (dict, list)):
                        recursive_modify(value, mods)
            elif isinstance(obj, list):
                for item in obj:
                    recursive_modify(item, mods)

        recursive_modify(data, modifications)
        return json.dumps(data, separators=(',', ':')).encode() if modified else None
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

def process_packet(pkt, modifications, stream_deltas):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt[TCP].payload:
        return stream_deltas

    ip = pkt[IP]
    tcp = pkt[TCP]
    raw = bytes(tcp.payload)
    original_payload_len = len(raw)
    new_payload = raw  # 默认不修改

    # 解析并修改HTTP/2数据
    try:
        offset = 0
        new_payload = b''
        while offset + 9 <= len(raw):
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            if frame_len == 0:
                new_payload += raw[offset:frame_end]
                offset = frame_end
                continue

            if frame_type == 0x0:  # DATA帧
                modified_data = process_http2_data_frame(frame_data, modifications)
                if modified_data is not None:
                    frame_header.length = len(modified_data)
                    new_payload += bytes(frame_header)[:9] + modified_data
                else:
                    new_payload += raw[offset:frame_end]
            else:
                new_payload += raw[offset:frame_end]

            offset = frame_end

        # 处理剩余数据
        if offset < len(raw):
            new_payload += raw[offset:]
    except Exception as e:
        print(f"处理HTTP/2数据时出错: {e}")
        new_payload = raw  # 出错时保留原始数据

    # 计算载荷变化量
    delta_tcp = len(new_payload) - original_payload_len
    if delta_tcp == 0 and new_payload == raw:
        return stream_deltas  # 无变化

    # 更新TCP载荷
    tcp.remove_payload()
    tcp.add_payload(Raw(new_payload))

    # 获取五元组和流信息
    src_ip = ip.src
    src_port = tcp.sport
    dst_ip = ip.dst
    dst_port = tcp.dport
    stream_key = (src_ip, src_port, dst_ip, dst_port)
    reverse_stream_key = (dst_ip, dst_port, src_ip, src_port)

    # 应用当前流的SEQ调整
    seq_delta = stream_deltas.get(stream_key, 0)
    tcp.seq += seq_delta

    # 应用反向流的ACK调整
    ack_delta = stream_deltas.get(reverse_stream_key, 0)
    if tcp.ack != 0:
        tcp.ack += ack_delta

    # 更新流调整量
    if delta_tcp != 0:
        stream_deltas[stream_key] = stream_deltas.get(stream_key, 0) + delta_tcp

    # 删除校验和字段以强制Scapy重新计算
    del ip.chksum
    del tcp.chksum

    # 重新构建数据包以确保长度正确
    new_pkt = IP(bytes(ip))
    return stream_deltas

# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"
PCAP_OUT = "pcap/N16_modified19.pcap"

MODIFICATIONS = {
    "supi": "imsi-460012300000001",
    "pei": "imeisv-8645600000000111",
    "gpsi": "msisdn-8613900000001",
    "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
    "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "50000001"},
    "ueIpv4Address": "100.0.0.1",
    "nrCellId": "010000001",
    "dnn": "dnn-10000001"
}

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified_packets = []
stream_deltas = {}

for pkt in packets:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        modified_pkt = pkt.copy()
        stream_deltas = process_packet(modified_pkt, MODIFICATIONS, stream_deltas)
        modified_packets.append(modified_pkt)
    else:
        modified_packets.append(pkt)

print(f"保存修改后的PCAP到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)