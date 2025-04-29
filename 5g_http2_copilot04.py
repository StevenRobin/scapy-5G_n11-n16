from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re

# 配置参数
TARGET_FIELDS = {
    "supi": "imsi-460030100000022",  # 替换为新的 SUPI 值
}
PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_create_50p_mod_fixed09.pcap"


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


def modify_http2_path(raw_payload, old_imsi, new_supi):
    """修改HTTP/2头部中的路径URL"""
    decoder = Decoder()
    encoder = Encoder()
    try:
        # 解码HTTP/2头部
        headers = decoder.decode(raw_payload)
        modified = False

        for i, (key, value) in enumerate(headers):
            if key.lower() == ":path" and old_imsi in value:
                # 确保新 SUPI 值长度与原 IMSI 值长度一致
                if len(new_supi) != len(old_imsi):
                    print(f"[!] 替换失败: 新 SUPI 值长度 ({len(new_supi)}) 与原 IMSI 值长度 ({len(old_imsi)}) 不一致")
                    continue
                print(f"[+] 修改URL路径 {value} -> {value.replace(old_imsi, new_supi)}")
                headers[i] = (key, value.replace(old_imsi, new_supi))
                modified = True

        # 如果没有修改，直接返回None
        if not modified:
            return None

        # 尝试重新编码HTTP/2头部
        return encoder.encode(headers)

    except IndexError as e:
        # 捕获动态表索引错误
        print(f"[!] HPACK动态表索引错误: {str(e)}")
        return None
    except Exception as e:
        # 捕获其他错误
        print(f"[!] HTTP/2路径修改错误: {str(e)}")
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


def process_packet(pkt, last_seq, modify_url=False, old_imsi=None, new_supi=None):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset + 9 <= len(raw):
            # 解析帧头
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            # 修改HEADERS帧（类型0x1）
            if frame_type == 0x1 and modify_url:
                modified_frame_data = modify_http2_path(frame_data, old_imsi, new_supi)
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

# 替换配置
OLD_IMSI = "imsi-460030100000000"  # 原始IMSI值
NEW_SUPI = TARGET_FIELDS["supi"]   # 新SUPI值

for idx, pkt in enumerate(packets):
    if TCP in pkt and Raw in pkt:
        # 仅对第47和第49个报文进行URL修改
        if idx + 1 in [47, 49]:
            process_packet(pkt, last_seq, modify_url=True, old_imsi=OLD_IMSI, new_supi=NEW_SUPI)
        else:
            process_packet(pkt, last_seq, modify_url=False)
    modified.append(pkt)

print(f"保存修改到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified)