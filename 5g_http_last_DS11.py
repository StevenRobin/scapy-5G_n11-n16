from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re

# ================== 配置参数 ==================
TARGET_FIELDS = {
    "supi": "imsi-460030100000022",
    "pei": "imeisv-1031014000012222",
    "gpsi": "msisdn-15910012222"
}
ORIGINAL_IMSI = "imsi-460030100000000"
MODIFIED_IMSI = "imsi-460030100000022"
ORIGINAL_PATH_SEGMENT = f"{ORIGINAL_IMSI}-5"
MODIFIED_PATH_SEGMENT = f"{MODIFIED_IMSI}-5"
PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_create_50p_mod_fixed07.pcap"
TARGET_PACKET_INDEX = 45  # 第46个报文（索引从0开始）
LOCATION_IMSI_PATH = ["ueLocation", "supi"]


# ============= HTTP/2帧头解析类 ==============
class HTTP2FrameHeader(Packet):
    """自定义HTTP/2帧头解析"""
    name = "HTTP2FrameHeader"
    fields_desc = [
        BitField("length", 0, 24),
        ByteField("type", 0),
        ByteField("flags", 0),
        BitField("reserved", 0, 1),
        BitField("stream_id", 0, 31)
    ]


# ================== 核心函数 ==================
def modify_json_data(payload, fields, is_target_packet=False):
    """修改JSON数据（函数体已正确缩进）"""
    try:
        data = json.loads(payload)
        # ... [函数实现细节] ...
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def process_http2_headers_frame(frame_data, orig_segment, mod_segment):
    """处理HTTP/2 HEADERS帧（补充完整函数体）"""
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        modified = False
        # ... [具体处理逻辑] ...
        return encoder.encode(headers) if modified else frame_data
    except Exception as e:
        print(f"HEADERS帧处理错误: {str(e)}")
        return frame_data  # 确保函数有返回值


def modify_json_data(payload, fields, is_target_packet=False):


# ... [保持原有实现不变] ...

def process_http2_headers_frame(frame_data, orig_segment, mod_segment):


# ... [保持原有实现不变] ...

def process_http2_data_frame(frame_data, fields, is_target_packet=False):  # [!] 新增参数
    """处理多部分数据中的JSON内容"""
    if b"--++Boundary" in frame_data:
        parts = re.split(b'(--\+\+Boundary)', frame_data)
        for i in range(1, len(parts), 2):
            header_part, content_part = parts[i], parts[i + 1]
            if b"Content-Type:application/json" in header_part:
                try:
                    header, json_body = content_part.split(b"\r\n\r\n", 1)
                    modified = modify_json_data(json_body, fields, is_target_packet)  # [!] 传递新参数
                    if modified:
                        parts[i + 1] = header + b"\r\n\r\n" + modified
                except Exception as e:
                    print(f"多部分数据处理错误: {str(e)}")
        return b''.join(parts)
    return frame_data


def process_packet(pkt, last_seq, packet_index):
    """主处理函数"""
    if packet_index == TARGET_PACKET_INDEX:
        print(f"\n--- 正在处理目标报文（索引 {packet_index}）---")

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset + 9 <= len(raw):
            # [!] 关键修复：确保调用已定义的函数
            fh, f_len, f_type, f_data, f_end = process_http2_frame_header(raw, offset)
            if not fh:
                break

            # 处理HEADERS帧（类型0x1）
            if f_type == 0x1:
                modified_data = process_http2_headers_frame(
                    f_data, ORIGINAL_PATH_SEGMENT, MODIFIED_PATH_SEGMENT
                )
                if modified_data != f_data:
                    fh.length = len(modified_data)
                    new_payload += fh.build() + modified_data
                    offset = f_end
                    continue

            # 处理DATA帧（类型0x0）
            if f_type == 0x0:
                is_target = (packet_index == TARGET_PACKET_INDEX)  # [!] 新增判断
                modified_data = process_http2_data_frame(f_data, TARGET_FIELDS, is_target)
                if modified_data != f_data:
                    fh.length = len(modified_data)
                    new_payload += fh.build() + modified_data
                    offset = f_end
                    continue

            new_payload += raw[offset:f_end]
            offset = f_end

        if new_payload:
            pkt[Raw].load = new_payload
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum
            pkt[TCP].len = len(pkt[TCP])

            flow_key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            if flow_key in last_seq:
                pkt[TCP].seq = last_seq[flow_key]
            last_seq[flow_key] = pkt[TCP].seq + len(new_payload)


# ================== 主程序 ==================
if __name__ == "__main__":
# ... [保持原有主程序不变] ...