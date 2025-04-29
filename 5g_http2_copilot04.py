from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re

# 配置参数（直接写入修改值）
PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_create_50p_modified.pcap"
ORIGINAL_IMSI = "imsi-460030100000000"  # 原始IMSI
MODIFIED_IMSI = "imsi-460030100000022"  # 修改后的IMSI

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


def modify_json_data(payload, fields):
    """修改JSON数据中的目标字段"""
    try:
        data = json.loads(payload)
        modified = False
        for key in list(data.keys()):  # 创建副本避免修改时迭代错误
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


def process_http2_headers_frame(frame_data, original_imsi, modified_imsi):
    """处理HTTP/2 HEADERS帧中的路径"""
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        modified = False

        for i in range(len(headers)):
            name, value = headers[i]
            if name.lower() == ":path":
                if original_imsi in value:
                    new_value = value.replace(original_imsi, modified_imsi)
                    headers[i] = (name, new_value)
                    print(f"[+] 修改URL路径: {value} -> {new_value}")
                    modified = True

        if modified:
            encoder = Encoder()
            new_data = encoder.encode(headers)
            return new_data
        return frame_data
    except Exception as e:
        print(f"HEADERS帧处理错误: {str(e)}")
        return frame_data


def process_http2_data_frame(frame_data, fields):
    """处理HTTP/2 DATA帧中的多部分数据"""
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


def process_http2_frame_header(raw, offset):
    """解析HTTP/2帧头部"""
    try:
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        stream_id = frame_header.stream_id  # 虽然未使用但保留原始结构
        frame_end = offset + 9 + frame_len
        frame_data = raw[offset + 9:frame_end]
        return frame_header, frame_len, frame_type, frame_data, frame_end
    except Exception as e:
        print(f"帧解析错误: {str(e)}")
        return None, None, None, None, None


def process_packet(pkt, last_seq, original_imsi, modified_imsi, target_fields):
    """处理单个TCP包"""
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset + 9 <= len(raw):
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            # 处理HEADERS帧（类型0x1）
            if frame_type == 0x1:
                modified_frame_data = process_http2_headers_frame(frame_data, original_imsi, modified_imsi)
                if modified_frame_data != frame_data:
                    frame_len = len(modified_frame_data)
                    frame_header.length = frame_len
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    continue

            # 处理DATA帧（类型0x0）
            if frame_type == 0x0:
                modified_frame_data = process_http2_data_frame(frame_data, target_fields)
                if modified_frame_data != frame_data:
                    frame_len = len(modified_frame_data)
                    frame_header.length = frame_len
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    continue

            new_payload += raw[offset:frame_end]
            offset = frame_end

        if new_payload:
            pkt[Raw].load = new_payload
            pkt[IP].len = len(pkt[IP])
            pkt[TCP].len = pkt[IP].len - (pkt[IP].ihl * 4)
            del pkt[IP].chksum
            del pkt[TCP].chksum

            flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            if flow in last_seq:
                pkt[TCP].seq = last_seq[flow]
            last_seq[flow] = pkt[TCP].seq + len(pkt[Raw].load)


def main():
    print(f"开始处理文件 {PCAP_IN}")
    packets = rdpcap(PCAP_IN)
    modified = []

    last_seq = {}
    TARGET_FIELDS = {
        "supi": MODIFIED_IMSI.replace("imsi-", ""),  # 提取IMSI数字部分作为SUPI
        "pei": "imeisv-1031014000012222",  # 示例替换字段
        "gpsi": "msisdn-15910012222"       # 示例替换字段
    }

    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            process_packet(pkt, last_seq, ORIGINAL_IMSI, MODIFIED_IMSI, TARGET_FIELDS)
        modified.append(pkt)

    print(f"保存修改到 {PCAP_OUT}")
    wrpcap(PCAP_OUT, modified)


if __name__ == "__main__":
    main()