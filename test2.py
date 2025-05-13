from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re
from collections import defaultdict


# ================= 自定义 HTTP/2 帧头解析 =================
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


def modify_http2_headers(frame_data, target_headers):
    """修改 HTTP/2 HEADERS 帧中的path、authority等伪首部字段"""
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        modified = False
        new_headers = []

        for name, value in headers:
            lname = name.lower()
            if lname in target_headers:
                print(f"[+] 修改Header {name}: {value} -> {target_headers[lname]}")
                new_headers.append((name, target_headers[lname]))
                modified = True
            else:
                new_headers.append((name, value))

        if modified:
            encoder = Encoder()
            return encoder.encode(new_headers)
        return frame_data
    except Exception as e:
        print(f"HEADERS帧处理错误: {str(e)}")
        return frame_data


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


def process_packet(pkt, modifications, seq_diff, ip_replacements, header_mods):
    """处理单个数据包"""
    if pkt.haslayer(IP):
        # 修改五元组 IP 地址对
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
        original_length = len(raw)
        modified = False

        while offset < len(raw):
            if offset + 9 > len(raw):
                new_payload += raw[offset:]
                break

            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                new_payload += raw[offset:]
                break

            if frame_type == 0x1 and header_mods:  # HEADERS frame
                modified_frame_data = modify_http2_headers(frame_data, header_mods)
                if modified_frame_data != frame_data:
                    frame_header.length = len(modified_frame_data)
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    modified = True
                    continue

            if frame_type == 0x0:  # DATA frame
                modified_frame_data = process_http2_data_frame(frame_data, modifications)
                if modified_frame_data and modified_frame_data != frame_data:
                    frame_header.length = len(modified_frame_data)
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    modified = True
                    continue

            new_payload += raw[offset:frame_end]
            offset = frame_end

        if modified:
            pkt[Raw].load = new_payload

            # 计算长度差并更新序列号
            diff = len(new_payload) - original_length
            flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            if flow not in seq_diff:
                seq_diff[flow] = 0

            # 更新序列号
            pkt[TCP].seq += seq_diff[flow]
            seq_diff[flow] += diff

            # 删除校验和字段以便重新计算
            if hasattr(pkt[IP], 'chksum'):
                del pkt[IP].chksum
            if hasattr(pkt[TCP], 'chksum'):
                del pkt[TCP].chksum
            if hasattr(pkt[IP], 'len'):
                del pkt[IP].len

            # 更新数据包长度
            pkt.wirelen = len(pkt)
            pkt.caplen = pkt.wirelen


# =================== 主处理流程 ====================
def main():
    # 配置文件路径
    PCAP_IN = "pcap/N16_create_16p.pcap"
    PCAP_OUT = "pcap/N16_modified111.pcap"

    # JSON 字段修改内容
    MODIFICATIONS = {
        "supi": "imsi-460012300000001",
        "pei": "imeisv-8611101000000011",
        "gpsi": "msisdn-8613900000001",
        "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
        "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "50000001"},
        "ueIpv4Address": "100.0.0.1",
        "nrCellId": "010000001",
        "uplink": "5000000000",
        "downlink": "5000000000",
        "ismfPduSessionUri": "http://30.0.0.1:80/nsmf-pdusession/v1/pdu-sessions/10000001"
    }

    # HEADERS 伪首部字段修改内容
    HEADER_MODIFICATIONS = {
        ":path": "/nsmf-pdusession/v1/sm-contexts/1000000001/retrieve",  # 修改为你想要的新路径
        ":authority": "smf.smf"  # 修改为你想要的新域名
    }

    # 五元组 IP 替换内容
    IP_REPLACEMENTS = {
        "200.20.20.26": "30.0.0.1",
        "200.20.20.25": "40.0.0.1"
    }

    print(f"开始处理文件 {PCAP_IN}")

    # 读取数据包
    packets = rdpcap(PCAP_IN)
    modified_packets = []

    # 初始化序列号差异跟踪
    seq_diff = {}

    # 处理每个数据包
    for pkt in packets:
        if TCP in pkt or Raw in pkt:
            process_packet(pkt, MODIFICATIONS, seq_diff, IP_REPLACEMENTS, HEADER_MODIFICATIONS)
        modified_packets.append(pkt)

    print(f"保存修改后的 PCAP 到 {PCAP_OUT}")
    wrpcap(PCAP_OUT, modified_packets)


if __name__ == "__main__":
    main()