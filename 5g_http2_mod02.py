from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField, StrLenField
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
PCAP_OUT = "pcap/N11_create_50p_mod.pcap"


# 自定义HTTP/2帧头解析（替代scapy.layers.http2）
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


def process_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset + 9 <= len(raw):
            # 解析帧头
            try:
                frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
                frame_len = frame_header.length
                frame_type = frame_header.type
                stream_id = frame_header.stream_id
                frame_end = offset + 9 + frame_len
                frame_data = raw[offset + 9:frame_end]

                # 处理DATA帧（类型0x0）
                if frame_type == 0x0:
                    # 检测multipart边界
                    if b"--++Boundary" in frame_data:
                        parts = re.split(b'(--\+\+Boundary)', frame_data)

                        for i in range(len(parts)):
                            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                                # 查找JSON部分
                                if b"Content-Type:application/json" in parts[i + 1]:
                                    json_part = parts[i + 1].split(b"\r\n\r\n", 1)[1]
                                    modified = modify_json_data(json_part, TARGET_FIELDS)
                                    if modified:
                                        parts[i + 1] = parts[i + 1].split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n" + modified

                        frame_data = b''.join(parts)
                        frame_len = len(frame_data)
                        # 重建帧头
                        new_header = HTTP2FrameHeader(
                            length=frame_len,
                            type=frame_type,
                            flags=frame_header.flags,
                            stream_id=stream_id
                        ).build()

                        new_payload += new_header + frame_data
                        offset = frame_end
                        continue

                # 保留未修改的帧
                new_payload += raw[offset:frame_end]
                offset = frame_end

            except Exception as e:
                print(f"帧解析错误: {str(e)}")
                break

        # 更新原始载荷
        if new_payload:
            pkt[Raw].load = new_payload
            # 删除自动校验和
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum


# 主处理流程
print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified = []
for pkt in packets:
    if TCP in pkt and Raw in pkt:
        process_packet(pkt)
    modified.append(pkt)

print(f"保存修改到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified)