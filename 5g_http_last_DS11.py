from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re

# 配置参数
TARGET_FIELDS = {
    "supi": "imsi-460030100000022",
    "pei": "imeisv-1031014000012222",
    "gpsi": "msisdn-15910012222"
}
ORIGINAL_IMSI = "imsi-460030100000000"
MODIFIED_IMSI = "imsi-460030100000022"
PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_create_50p_mod_fixed07.pcap"
SPECIFIC_PACKET_INDEX = 48  # 第49个报文（索引从0开始）
OLD_PATH = "/nsmf-pdusession/v1/sm-contexts/imsi-460030100000000-5/modify"
NEW_PATH = "imsi-460030100000022"


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


def modify_json_data(payload, fields):
    try:
        data = json.loads(payload)
        modified = False
        for key in list(data.keys()):
            lkey = key.lower()
            for target in fields:
                if target.lower() == lkey:
                    print(f"[+] 修改JSON字段 {key} ({data[key]}) -> {fields[target]}")
                    data[key] = fields[target]
                    modified = True
        return json.dumps(data, indent=None).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None


def process_http2_headers_frame(frame_data, original_imsi, modified_imsi, is_specific_packet=False):
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        modified = False

        for i in range(len(headers)):
            name, value = headers[i]
            if name.lower() == ":path":
                # 特定报文处理
                if is_specific_packet and value == OLD_PATH:
                    headers[i] = (name, NEW_PATH)
                    print(f"[!] 特殊修改URL路径: {OLD_PATH} -> {NEW_PATH}")
                    modified = True
                # 常规IMSI替换
                elif original_imsi in value:
                    new_value = value.replace(original_imsi, modified_imsi)
                    headers[i] = (name, new_value)
                    print(f"[+] 修改URL路径: {value} -> {new_value}")
                    modified = True

        if modified:
            encoder = Encoder()
            return encoder.encode(headers)
        return frame_data
    except Exception as e:
        print(f"HEADERS帧处理错误: {str(e)}")
        return frame_data


def process_http2_data_frame(frame_data, fields):
    if b"--++Boundary" in frame_data:
        parts = re.split(b'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    json_part = parts[i + 1].split(b"\r\n\r\n", 1)[1]
                    modified = modify_json_data(json_part, fields)
                    if modified:
                        parts[i + 1] = parts[i + 1].split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n" + modified
        return b''.join(parts)
    return frame_data


def process_packet(pkt, last_seq, packet_index):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset + 9 <= len(raw):
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            is_target_packet = (packet_index == SPECIFIC_PACKET_INDEX)

            if frame_type == 0x1:
                modified_frame_data = process_http2_headers_frame(
                    frame_data,
                    ORIGINAL_IMSI,
                    MODIFIED_IMSI,
                    is_specific_packet=is_target_packet  # 传递是否目标报文
                )

            elif frame_type == 0x0:
                modified_frame_data = process_http2_data_frame(frame_data, TARGET_FIELDS)
            else:
                modified_frame_data = frame_data

            if modified_frame_data != frame_data:
                frame_header.length = len(modified_frame_data)
                new_payload += frame_header.build() + modified_frame_data
            else:
                new_payload += raw[offset:frame_end]

            offset = frame_end

        if new_payload:
            pkt[Raw].load = new_payload

        pkt[IP].len = len(pkt[IP])
        pkt[TCP].len = pkt[IP].len - (pkt[IP].ihl * 4)
        pkt.wirelen = len(pkt)
        del pkt[IP].chksum
        del pkt[TCP].chksum

        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        if flow in last_seq:
            pkt[TCP].seq = last_seq[flow]
        last_seq[flow] = pkt[TCP].seq + len(pkt[Raw].load)


print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified = []
last_seq = {}

for idx, pkt in enumerate(packets):
    if TCP in pkt and Raw in pkt:
        process_packet(pkt, last_seq, idx)  # 传递报文索引
    modified.append(pkt)

print(f"保存修改到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified)