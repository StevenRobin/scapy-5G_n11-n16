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

def modify_json_data(payload, modifications):
    """修改 JSON 数据中的目标字段"""
    try:
        if not payload.strip():
            print("[跳过空数据段]")
            return None
        data = json.loads(payload)
        modified = False

        def recursive_modify(obj, modifications):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in modifications:
                        print(f"[+] 修改 JSON 字段 {key}: {value} -> {modifications[key]}")
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
    """处理 HTTP/2 DATA 帧中的多部分数据"""
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    segments = parts[i + 1].split(b"\r\n\r\n", 1)
                    if len(segments) == 2:
                        json_part = segments[1]
                        modified = modify_json_data(json_part, modifications)
                        if modified:
                            parts[i + 1] = segments[0] + b"\r\n\r\n" + modified
        return b''.join(parts)
    else:
        modified = modify_json_data(frame_data, modifications)
        return modified if modified else frame_data

def patch_content_length_hpack(raw, length_map):
    """
    精准修正HTTP/2 HEADERS帧的HPACK编码content-length值和帧头部length字段
    """
    offset = 0
    result = b''
    while offset < len(raw):
        if offset + 9 > len(raw):
            result += raw[offset:]
            break

        frame_header = raw[offset:offset+9]
        frame_length = int.from_bytes(frame_header[0:3], 'big')
        frame_type = frame_header[3]
        frame_body = raw[offset+9:offset+9+frame_length]

        # 只处理HEADERS帧 (type==1)
        if frame_type == 1:
            try:
                decoder = Decoder()
                headers, consumed = decoder.decode(frame_body)
                new_headers = []
                changed = False
                for k, v in headers:
                    if k.lower() == b'content-length':
                        old_v = int(v)
                        if old_v in length_map:
                            print(f"[HPACK] patch content-length {old_v}→{length_map[old_v]}")
                            v = str(length_map[old_v]).encode()
                            changed = True
                    new_headers.append((k, v))
                if changed:
                    encoder = Encoder()
                    new_frame_body = encoder.encode(new_headers)
                    frame_length = len(new_frame_body)
                    frame_header = frame_length.to_bytes(3, 'big') + frame_header[3:]
                    frame_body = new_frame_body
            except Exception as e:
                print(f"HPACK decode fail: {e}")

        result += frame_header + frame_body
        offset += 9 + frame_length
    return result

def process_packet(pkt, modifications, seq_diff, ip_replacements):
    """
    对 TCP 包内部的 HTTP/2 数据帧进行处理：
    1. 解析所有 HTTP/2 帧，对 DATA 帧进行 JSON 数据修改。
    2. 修改五元组 IP 地址对。
    3. 追加未解析的剩余数据，防止丢失。
    4. 根据包内负载变化计算偏移量，累加调整 TCP 序号。
    5. 删除校验和字段，让 Scapy 自动重新生成。
    """
    if pkt.haslayer(IP):
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
            if offset + 9 > len(raw):
                new_payload += raw[offset:]
                offset = len(raw)
                break

            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if frame_header is None:
                break

            if frame_data and b"Content-Length" in frame_data:
                def replace_content_length(data):
                    def repl(match):
                        old_val = int(match.group(1))
                        if old_val == 348:
                            return b"Content-Length: 375"
                        elif old_val == 709:
                            return b"Content-Length: 771"
                        elif old_val == 353:
                            return b"Content-Length: 379"
                        else:
                            return match.group(0)
                    return re.sub(br"Content-Length: (\d+)", repl, data, count=1)
                frame_data = replace_content_length(frame_data)

            if frame_type == 0x0:
                modified_frame_data = process_http2_data_frame(frame_data, modifications)
                if modified_frame_data:
                    frame_len = len(modified_frame_data)
                    frame_header.length = frame_len
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    continue

            new_payload += frame_header.build() + frame_data
            offset = frame_end

        original_length = len(raw)
        new_length = len(new_payload)
        diff = new_length - original_length

        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        if flow not in seq_diff:
            seq_diff[flow] = 0
        pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
        seq_diff[flow] += diff

        pkt[Raw].load = new_payload

        if hasattr(pkt[IP], 'chksum'):
            del pkt[IP].chksum
        if hasattr(pkt[TCP], 'chksum'):
            del pkt[TCP].chksum
        if hasattr(pkt[IP], 'len'):
            del pkt[IP].len

        pkt.wirelen = len(pkt)
        pkt.caplen = pkt.wirelen

# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"
PCAP_OUT = "pcap/N16_modified114.pcap"

MODIFICATIONS = {
    "supi": "imsi-460012300000001",
    "pei": "imeisv-8611101000000011",
    "gpsi": "msisdn-8613900000001",
    "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
    "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "50000001"},
    "ueIpv4Address": "100.0.0.1",
    "nrCellId": "010000001",
    "ismfPduSessionUri": "http://200.20.20.26:8080/nsmf-pdusession/v1/pdu-sessions/10000001"
}

IP_REPLACEMENTS = {
    "200.20.20.26": "30.0.0.1",
    "200.20.20.25": "40.0.0.1"
}

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified_packets = []

seq_diff = {}
length_map = {348: 375, 709: 771, 353: 379}

for i, pkt in enumerate(packets):
    if TCP in pkt or Raw in pkt:
        process_packet(pkt, MODIFICATIONS, seq_diff, IP_REPLACEMENTS)

    # 仅对11、13、15号包处理content-length
    if i+1 in [11, 13, 15]:
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            new_payload = patch_content_length_hpack(raw, length_map)
            pkt[Raw].load = new_payload
            # 重新计算校验和等
            if hasattr(pkt[IP], 'chksum'):
                del pkt[IP].chksum
            if hasattr(pkt[TCP], 'chksum'):
                del pkt[TCP].chksum
            if hasattr(pkt[IP], 'len'):
                del pkt[IP].len

    modified_packets.append(pkt)

print(f"保存修改后的 PCAP 到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)