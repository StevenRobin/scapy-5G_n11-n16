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
# 新增路径段定义（包含-5）
ORIGINAL_PATH_SEGMENT = f"{ORIGINAL_IMSI}-5"
MODIFIED_PATH_SEGMENT = f"{MODIFIED_IMSI}-5"
PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_create_50p_mod_fixed07.pcap"

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
def process_http2_frame_header(raw, offset):
    """解析HTTP/2帧头部"""
    try:
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        frame_data = raw[offset + 9:offset + 9 + frame_len]
        frame_end = offset + 9 + frame_len
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
            if lkey in [k.lower() for k in fields]:
                print(f"[+] 修改JSON字段 {key}: {data[key]} -> {fields[key]}")
                data[key] = fields[key]
                modified = True
        return json.dumps(data, separators=(',', ':')).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def process_http2_headers_frame(frame_data, orig_segment, mod_segment):
    """精确处理HTTP/2 HEADERS帧中的路径"""
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        modified = False

        for i in range(len(headers)):
            name, value = headers[i]
            if name.lower() == ":path" and orig_segment in value:
                new_value = value.replace(orig_segment, mod_segment)
                headers[i] = (name, new_value)
                print(f"[+] 修改URL路径: {value[:50]}... -> {new_value[:50]}...")
                modified = True

        if modified:
            encoder = Encoder()
            return encoder.encode(headers)
        return frame_data
    except Exception as e:
        print(f"HEADERS帧处理错误: {str(e)}")
        return frame_data

def process_http2_data_frame(frame_data, fields):
    """处理多部分数据中的JSON内容"""
    if b"--++Boundary" in frame_data:
        parts = re.split(b'(--\+\+Boundary)', frame_data)
        for i in range(1, len(parts), 2):
            header_part, content_part = parts[i], parts[i+1]
            if b"Content-Type:application/json" in header_part:
                try:
                    header, json_body = content_part.split(b"\r\n\r\n", 1)
                    modified = modify_json_data(json_body, fields)
                    if modified:
                        parts[i+1] = header + b"\r\n\r\n" + modified
                except Exception as e:
                    print(f"多部分数据处理错误: {str(e)}")
        return b''.join(parts)
    return frame_data

def process_packet(pkt, last_seq):
    """主处理函数"""
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''

        while offset + 9 <= len(raw):
            # 解析帧头
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
                modified_data = process_http2_data_frame(f_data, TARGET_FIELDS)
                if modified_data != f_data:
                    fh.length = len(modified_data)
                    new_payload += fh.build() + modified_data
                    offset = f_end
                    continue

            # 保留未修改的帧
            new_payload += raw[offset:f_end]
            offset = f_end

        # 更新数据包内容
        if new_payload:
            pkt[Raw].load = new_payload
            # 更新网络层和传输层信息
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum
            pkt[TCP].len = len(pkt[TCP])

            # 维护TCP序列号
            flow_key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            if flow_key in last_seq:
                pkt[TCP].seq = last_seq[flow_key]
            last_seq[flow_key] = pkt[TCP].seq + len(new_payload)

# ================== 主程序 ==================
if __name__ == "__main__":
    print(f"开始处理文件: {PCAP_IN}")
    packets = rdpcap(PCAP_IN)
    last_seq = {}
    modified_pkts = []

    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            process_packet(pkt, last_seq)
        modified_pkts.append(pkt)

    print(f"保存修改到: {PCAP_OUT}")
    wrpcap(PCAP_OUT, modified_pkts)
    print("处理完成！修改统计：")
    print(f"- URL路径修改次数: {len([p for p in modified_pkts if '修改URL路径' in str(p)])}")
    print(f"- JSON字段修改次数: {len([p for p in modified_pkts if '修改JSON字段' in str(p)])}")