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
PCAP_OUT = "pcap/N11_create_50p_mod_fixed11.pcap"


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


def modify_json_data(payload, fields):
    """修改JSON数据中的目标字段"""
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
            return encoder.encode(headers)
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


class StreamTracker:
    """TCP流序列号跟踪器"""

    def __init__(self):
        self.streams = {}  # key: (src, dst, sport, dport), value: (next_seq, next_ack)

    def update_stream(self, pkt, payload_len):
        """更新流的序列号状态"""
        flow_key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        reverse_flow_key = (pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport)

        # 处理正向流
        if flow_key in self.streams:
            expected_seq, expected_ack = self.streams[flow_key]
            if pkt[TCP].seq != expected_seq:
                print(f"[!] 序列号异常: 预期 {expected_seq}, 实际 {pkt[TCP].seq}")
            self.streams[flow_key] = (expected_seq + payload_len, expected_ack)
        else:
            self.streams[flow_key] = (pkt[TCP].seq + payload_len, pkt[TCP].ack)

        # 处理反向流的确认号
        if reverse_flow_key in self.streams:
            rev_seq, rev_ack = self.streams[reverse_flow_key]
            if pkt[TCP].ack != rev_ack:
                print(f"[!] 确认号异常: 预期 {rev_ack}, 实际 {pkt[TCP].ack}")


def process_packet(pkt, tracker):
    """处理单个报文"""
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''
        original_payload_len = len(raw)
        modified_payload_len = 0

        # 处理HTTP/2帧
        while offset + 9 <= len(raw):
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            # 处理HEADERS帧
            if frame_type == 0x1:
                modified_data = process_http2_headers_frame(frame_data, ORIGINAL_IMSI, MODIFIED_IMSI)
                if modified_data != frame_data:
                    frame_header.length = len(modified_data)
                    new_payload += frame_header.build() + modified_data
                    offset = frame_end
                    continue

            # 处理DATA帧
            if frame_type == 0x0:
                modified_data = process_http2_data_frame(frame_data, TARGET_FIELDS)
                if modified_data != frame_data:
                    frame_header.length = len(modified_data)
                    new_payload += frame_header.build() + modified_data
                    offset = frame_end
                    continue

            new_payload += raw[offset:frame_end]
            offset = frame_end

        # 更新载荷
        if new_payload:
            pkt[Raw].load = new_payload
            modified_payload_len = len(new_payload)
            print(f"[*] 载荷修改: 原长度 {original_payload_len} -> 新长度 {modified_payload_len}")

        # 更新IP/TCP头
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum
        pkt[TCP].dataofs = 5  # 强制TCP头长度为20字节

        # 更新序列号跟踪
        tracker.update_stream(pkt, modified_payload_len if new_payload else original_payload_len)

    return pkt


# ---------------------- 主处理流程 ----------------------
print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
tracker = StreamTracker()

modified_packets = []
for pkt in packets:
    if IP in pkt and TCP in pkt:
        modified_pkt = process_packet(pkt.copy(), tracker)
        modified_packets.append(modified_pkt)
    else:
        modified_packets.append(pkt)

print(f"保存修改到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)