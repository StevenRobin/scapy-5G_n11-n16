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
        # 当帧体长度超过剩余捕获数据时，使用剩余长度
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
        # 跳过空数据段
        if not payload.strip():
            print("[跳过空数据段]")
            return None
        data = json.loads(payload)
        modified = False

        def recursive_modify(obj, modifications):
            """递归修改嵌套 JSON 对象"""
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
        return json.dumps(data, separators=(',', ':')).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def process_http2_data_frame(frame_data, modifications):
    """处理 HTTP/2 DATA 帧中的多部分数据，并返回实际的JSON数据长度"""
    json_length = 0
    modified_data = None

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
                            json_length = len(modified)  # 使用修改后的JSON长度
                        else:
                            json_length = len(json_part)  # 使用原始JSON长度
        modified_data = b''.join(parts)
    else:
        try:
            # 尝试解析为JSON
            if frame_data.strip():
                modified = modify_json_data(frame_data, modifications)
                if modified:
                    modified_data = modified
                    json_length = len(modified)  # 使用修改后的JSON长度
                else:
                    modified_data = frame_data
                    json_length = len(frame_data)  # 使用原始JSON长度
        except Exception as e:
            print(f"JSON解析错误: {str(e)}")
            modified_data = frame_data
            json_length = len(frame_data)

    return modified_data, json_length

def process_http2_headers_frame(frame_data, context_num, data_length=None):
    """处理 HTTP/2 HEADERS 帧，修改 path 和 authority 字段，更新 content-length"""
    try:
        decoder = Decoder()
        encoder = Encoder()
        headers = decoder.decode(frame_data)
        modified = False
        new_headers = []
        content_length_added = False

        # 第一遍：收集除content-length外的所有headers
        for name, value in headers:
            if name.lower() != "content-length":  # 忽略所有content-length字段
                if name == ":path":
                    new_path = f"/nsmf-pdusession/v1/sm-contexts/{context_num}/retrieve"
                    print(f"[+] 修改 header {name}: {value} -> {new_path}")
                    new_headers.append((name, new_path))
                    modified = True
                elif name == ":authority":
                    new_authority = "smf.smf"
                    print(f"[+] 修改 header {name}: {value} -> {new_authority}")
                    new_headers.append((name, new_authority))
                    modified = True
                else:
                    new_headers.append((name, value))

        # 第二遍：如果有DATA帧，添加一个准确的content-length
        if data_length is not None and data_length > 0:
            print(f"[+] 设置 content-length: {data_length}")
            new_headers.append(("content-length", str(data_length)))
            modified = True

        if modified:
            return encoder.encode(new_headers)
        return frame_data
    except Exception as e:
        print(f"Header处理错误: {str(e)}")
        return frame_data

def calculate_data_frame_length(raw, offset):
    """计算HTTP/2 DATA帧的实际数据长度"""
    data_frames = []  # 存储所有DATA帧的信息
    current_offset = offset
    total_length = 0

    while current_offset < len(raw):
        if current_offset + 9 > len(raw):
            break

        frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, current_offset)
        if frame_header is None:
            break

        if frame_type == 0x0:  # DATA帧
            data_frames.append((frame_len, frame_data))
            total_length = frame_len  # 只使用最后一个DATA帧的长度

        current_offset = frame_end

    return total_length

def process_packet(pkt, modifications, seq_diff, ip_replacements, context_num):
    """
    对 TCP 包内部的 HTTP/2 数据帧进行处理：
    1. 解析所有 HTTP/2 帧，修改 HEADERS 帧中的 path 和 authority。
    2. 对 DATA 帧进行 JSON 数据修改。
    3. 修改五元组 IP 地址对。
    4. 追加未解析的剩余数据，防止丢失。
    5. 根据包内负载变化计算偏移量，累加调整 TCP 序号。
    6. 删除校验和字段，让 Scapy 自动重新生成。
    """
    if pkt.haslayer(IP):
        # 修改五元组 IP 地址对
        if pkt[IP].src in ip_replacements:
            print(f"[+] 替换源IP {pkt[IP].src} -> {ip_replacements[pkt[IP].src]}")
            pkt[IP].src = ip_replacements[pkt[IP].src]
        if pkt[IP].dst in ip_replacements:
            print(f"[+] 替换目的IP {pkt[IP].dst} -> {ip_replacements[pkt[IP].dst]}")
            pkt[IP].dst = ip_replacements[pkt[IP].dst]

    if pkt.haslayer(TCP):
        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        rev_flow = (pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport)
        if flow not in seq_diff:
            seq_diff[flow] = 0
        if rev_flow not in seq_diff:
            seq_diff[rev_flow] = 0

        flags = pkt[TCP].flags
        is_syn = flags & 0x02 != 0
        is_fin = flags & 0x01 != 0
        is_rst = flags & 0x04 != 0
        has_payload = pkt.haslayer(Raw) and len(pkt[Raw].load) > 0

        diff = 0
        new_payload = None

        # 只对SYN/FIN/RST以外的有效payload包做累计
        if has_payload and not (is_syn or is_fin or is_rst):
            raw = bytes(pkt[Raw].load)
            offset = 0
            new_payload = b''
            json_length = None
            has_headers = False
            has_data = False
            data_frame_info = None

            # 第一遍扫描：查找DATA帧并获取JSON长度
            current_offset = 0
            while current_offset < len(raw):
                if current_offset + 9 > len(raw):
                    break
                frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, current_offset)
                if frame_header is None:
                    break
                if frame_type == 0x1:  # HEADERS帧
                    has_headers = True
                elif frame_type == 0x0:  # DATA帧
                    has_data = True
                    # 保存DATA帧信息以供后续处理
                    data_frame_info = (frame_data, frame_len)
                current_offset = frame_end

            # 如果找到DATA帧，先处理它以获取实际的JSON长度
            if data_frame_info:
                frame_data, _ = data_frame_info
                _, json_length = process_http2_data_frame(frame_data, modifications)

            # 第二遍扫描：处理所有帧
            while offset < len(raw):
                if offset + 9 > len(raw):
                    new_payload += raw[offset:]
                    offset = len(raw)
                    break

                frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
                if frame_header is None:
                    break

                if frame_type == 0x1:  # HEADERS帧
                    # 只有当包中同时存在HEADERS和DATA帧时才设置content-length
                    current_json_length = json_length if has_data else None
                    modified_frame_data = process_http2_headers_frame(frame_data, context_num, current_json_length)
                    if modified_frame_data:
                        frame_len = len(modified_frame_data)
                        frame_header.length = frame_len
                        new_payload += frame_header.build() + modified_frame_data
                        offset = frame_end
                        continue
                elif frame_type == 0x0:  # DATA帧
                    modified_frame_data, _ = process_http2_data_frame(frame_data, modifications)
                    if modified_frame_data:
                        frame_len = len(modified_frame_data)
                        frame_header.length = frame_len
                        new_payload += frame_header.build() + modified_frame_data
                        offset = frame_end
                        continue

                new_payload += raw[offset:frame_end]
                offset = frame_end

            original_length = len(raw)
            new_length = len(new_payload)
            diff = new_length - original_length
            pkt[Raw].load = new_payload

            # 修正seq/ack
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]
            # 只有有payload非SYN/FIN/RST才累计
            seq_diff[flow] += diff

        else:
            # 其它包（SYN/FIN/RST/无payload）只修正seq/ack，不累计
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]

        # 清空校验和和长度，交给 scapy 重算
        if hasattr(pkt[IP], 'chksum'):
            del pkt[IP].chksum
        if hasattr(pkt[TCP], 'chksum'):
            del pkt[TCP].chksum
        if hasattr(pkt[IP], 'len'):
            del pkt[IP].len

        pkt.wirelen = len(pkt)
        pkt.caplen = pkt.wirelen

# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"   # 输入 PCAP 文件路径
PCAP_OUT = "pcap/N16_154.pcap"   # 输出 PCAP 文件路径

# JSON 字段修改内容
MODIFICATIONS = {
    "supi": "imsi-460012300000001",
    "pei": "imeisv-8611101000000011",
    "gpsi": "msisdn-8613900000001",
    "dnn": "dnn12345",
    "ismfId": "c251849c-681e-48ba-918b-000010000001",
    "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
    "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "50000001"},
    "ueIpv4Address": "100.0.0.1",
    "nrCellId": "010000001",
    "uplink": "5000000000",
    "downlink": "5000000000",
    "ismfPduSessionUri": "http://30.0.0.1:80/nsmf-pdusession/v1/pdu-sessions/10000001"  # Updated ID
}

# 五元组 IP 替换内容
IP_REPLACEMENTS = {
    "200.20.20.26": "30.0.0.1",
    "200.20.20.25": "40.0.0.1"
}

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified_packets = []

# 保存每个流累计的 TCP 序号偏移量
seq_diff = {}
# 初始化context编号
context_num = 1000000001

for pkt in packets:
    if TCP in pkt or Raw in pkt:
        process_packet(pkt, MODIFICATIONS, seq_diff, IP_REPLACEMENTS, context_num)
        # 每处理一个包，context_num递增
        context_num += 1
    modified_packets.append(pkt)

print(f"保存修改后的 PCAP 到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets) 