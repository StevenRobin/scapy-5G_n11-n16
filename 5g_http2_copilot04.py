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
PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_create_50p_mod_with_url_fixed3.pcap"

# 新增需求：URL路径中的IMSI替换
URL_REPLACE_OLD = "imsi-460030100000000"
URL_REPLACE_NEW = "imsi-460030100000022"

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
                    print(f"[+] 修改字段 {key} ({data[key]}) -> {fields[target]}")
                    data[key] = fields[target]
                    modified = True
        return json.dumps(data, indent=None).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None


def modify_http2_path(raw_payload, old, new):
    """修改HTTP/2头部中的路径URL"""
    decoder = Decoder()
    encoder = Encoder()
    try:
        headers = decoder.decode(raw_payload)
        modified = False
        for i, (key, value) in enumerate(headers):
            if key.lower() == ":path" and old in value:
                print(f"[+] 修改URL路径 {value} -> {value.replace(old, new)}")
                headers[i] = (key, value.replace(old, new))
                modified = True
        return encoder.encode(headers) if modified else None
    except Exception as e:
        print(f"HTTP/2路径修改错误: {str(e)}")
        return None


def process_http2_frame_header(raw, offset):
    """解析HTTP/2帧头部"""
    try:
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        stream_id = frame_header.stream_id
        frame_end = offset + 9 + frame_len
        frame_data = raw[offset + 9:frame_end]
        return frame_header, frame_len, frame_type, frame_data, frame_end
    except Exception as e:
        print(f"帧解析错误: {str(e)}")
        return None, None, None, None, None


def process_packet(pkt, last_seq, modify_url=False):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset + 9 <= len(raw):
            # 解析帧头
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            # 修改DATA帧（类型0x0）或HEADERS帧（类型0x1）
            if frame_type in [0x0, 0x1] and modify_url:
                modified_frame_data = modify_http2_path(frame_data, URL_REPLACE_OLD, URL_REPLACE_NEW)
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
        pkt[IP].len = len(pkt[IP])
        pkt[TCP].len = pkt[IP].len - (pkt[IP].ihl * 4)

        # 删除校验和以强制重新计算
        del pkt[IP].chksum
        del pkt[TCP].chksum

        # 更新TCP序列号
        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        if flow in last_seq:
            pkt[TCP].seq = last_seq[flow]
        last_seq[flow] = pkt[TCP].seq + len(pkt[Raw].load)


# 主处理流程
print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified = []

# 记录每个流的最后TCP序列号
last_seq = {}

for idx, pkt in enumerate(packets):
    if TCP in pkt and Raw in pkt:
        # 仅对第47和第49个报文进行URL修改
        if idx + 1 in [47, 49]:
            process_packet(pkt, last_seq, modify_url=True)
        else:
            process_packet(pkt, last_seq, modify_url=False)
    modified.append(pkt)

print(f"保存修改到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified)