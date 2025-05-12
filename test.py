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
                for key in list(obj.keys()):
                    if key in mods:
                        print(f"[+] 修改JSON字段 {key}: {obj[key]} -> {mods[key]}")
                        obj[key] = mods[key]
                        modified = True
                    elif isinstance(obj[key], (dict, list)):
                        recursive_modify(obj[key], mods)
            elif isinstance(obj, list):
                for item in obj:
                    recursive_modify(item, mods)

        recursive_modify(data, modifications)
        return json.dumps(data, separators=(",", ":")).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None


def process_http2_headers(frame_data, modifications):
    """处理HTTP/2 HEADERS帧"""
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        encoder = Encoder()
        modified = False

        # 修改特定头字段
        for i in range(len(headers)):
            name, value = headers[i]
            if name in modifications:
                print(f"[+] 修改HEADER字段 {name}: {value} -> {modifications[name]}")
                headers[i] = (name, modifications[name])
                modified = True

        return encoder.encode(headers) if modified else None
    except Exception as e:
        print(f"HEADERS处理错误: {str(e)}")
        return None


def process_http2_data_frame(frame_data, modifications):
    """处理HTTP/2 DATA帧"""
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(1, len(parts), 2):
            header_part, content = parts[i + 1].split(b"\r\n\r\n", 1)
            if b"application/json" in header_part:
                modified = modify_json_data(content, modifications)
                if modified:
                    parts[i + 1] = header_part + b"\r\n\r\n" + modified
        return b''.join(parts)
    else:
        return modify_json_data(frame_data, modifications)


def process_packet(pkt, modifications, stream_info):
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return

    raw = bytes(pkt[Raw].load)
    new_payload = b''
    offset = 0

    while offset + 9 <= len(raw):
        frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
        if not frame_header:
            break

        modified_data = None

        # 处理HEADERS帧
        if frame_type == 0x01:
            modified_data = process_http2_headers(frame_data, modifications.get("headers", {}))

        # 处理DATA帧
        elif frame_type == 0x00:
            modified_data = process_http2_data_frame(frame_data, modifications.get("data", {}))

        if modified_data:
            # 更新帧长度
            frame_header.length = len(modified_data)
            new_payload += frame_header.build() + modified_data
        else:
            new_payload += raw[offset:frame_end]

        offset = frame_end

    if new_payload:
        # 更新TCP payload
        pkt[Raw].load = new_payload

        # 自动处理长度和校验和
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum

        # 处理TCP序列号
        flow_key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        payload_len = len(new_payload)

        if flow_key in stream_info:
            expected_seq = stream_info[flow_key]
            if pkt[TCP].seq != expected_seq:
                print(f"[!] 序列号不连续: 预期 {expected_seq} 实际 {pkt[TCP].seq}")
            pkt[TCP].seq = expected_seq
            stream_info[flow_key] += payload_len
        else:
            stream_info[flow_key] = pkt[TCP].seq + payload_len


# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"
PCAP_OUT = "pcap/N16_modified115.pcap"

MODIFICATIONS = {
    "data": {
        "supi": "imsi-460011234567890",
        "pei": "imeisv-8611101000000011",
        "gpsi": "msisdn-8613901000001",
        "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
        "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "20000001"},
        "ueIpv4Address": "100.0.0.1",
        "nrCellId": "001000001"
    },
    "headers": {
        "user-agent": "MyModifiedClient/1.0",
        "cookie": "modified_cookie=123456"
    }
}

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
stream_info = {}  # 保存每个流的序列号状态

for pkt in packets:
    if TCP in pkt and Raw in pkt:
        process_packet(pkt, MODIFICATIONS, stream_info)

print(f"保存修改后的PCAP到 {PCAP_OUT}")
wrpcap(PCAP_OUT, packets)