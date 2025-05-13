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
        return json.dumps(data, indent=None).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def process_http2_data_frame(frame_data, modifications):
    """处理 HTTP/2 DATA 帧中的多部分数据"""
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    # 按双 CRLF 分割获取 JSON 部分
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


def process_packet(pkt, modifications, seq_diff, ip_replacements, packet_number):
    """
    对 TCP 包内部的 HTTP/2 数据帧进行处理，增加调试信息打印
    """
    print(f"\n[调试] 正在处理第 {packet_number} 个数据包")  # 新增调试信息

    if pkt.haslayer(IP):
        # 修改五元组 IP 地址对
        if pkt[IP].src in ip_replacements:
            print(f"[+] 替换源IP {pkt[IP].src} -> {ip_replacements[pkt[IP].src]}")
            pkt[IP].src = ip_replacements[pkt[IP].src]
        if pkt[IP].dst in ip_replacements:
            print(f"[+] 替换目的IP {pkt[IP].dst} -> {ip_replacements[pkt[IP].dst]}")
            pkt[IP].dst = ip_replacements[pkt[IP].dst]

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        print(f"[调试] 数据包 {packet_number} 包含 TCP 和 Raw 层")  # 新增调试信息
        raw = bytes(pkt[Raw].load)
        print(f"[调试] Raw 数据长度: {len(raw)} 字节")  # 新增调试信息
        offset = 0
        new_payload = b''

        while offset < len(raw):
            if offset + 9 > len(raw):
                print(f"[调试] 数据包 {packet_number}: 剩余数据不足9字节，追加剩余数据")  # 新增调试信息
                new_payload += raw[offset:]
                offset = len(raw)
                break

            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if frame_header is None:
                print(f"[调试] 数据包 {packet_number}: 帧头解析失败")  # 新增调试信息
                break

            # 为特定包号(11,13,15)检查并打印Content-Length值
            # 为特定包号(11,13,15)检查并打印Content-Length值
            if packet_number in [11, 13, 15]:
                print(f"[调试] 检查数据包 {packet_number} 的 Content-Length")
                if frame_data:
                    print(f"[调试] 数据包 {packet_number} 帧数据长度: {len(frame_data)} 字节")
                    try:
                        frame_data_str = frame_data.decode('utf-8', errors='ignore')
                        print(f"[调试] 帧数据前100字节: {frame_data_str[:100]}")
                    except Exception as e:
                        print(f"[调试] 帧数据解码失败: {str(e)}")

                    # 修复正则表达式中的转义序列
                    match = re.search(br"content-length: *(\d+)", frame_data.lower())
                    if match:
                        content_length_value = match.group(1).decode('utf-8')
                        print(f"[包号 {packet_number}] Content-Length: {content_length_value}")
                    else:
                        print(f"[调试] 数据包 {packet_number} 未找到 Content-Length")

            # 处理 DATA 帧（类型为 0x0）
            if frame_type == 0x0:
                print(f"[调试] 数据包 {packet_number}: 处理 DATA 帧")  # 新增调试信息
                modified_frame_data = process_http2_data_frame(frame_data, modifications)
                if modified_frame_data:
                    frame_len = len(modified_frame_data)
                    frame_header.length = frame_len
                    new_payload += frame_header.build() + modified_frame_data
                    offset = frame_end
                    continue

            # 保留未修改的帧
            new_payload += raw[offset:frame_end]
            offset = frame_end

        # 若载荷被修改，则计算长度差
        original_length = len(raw)
        new_length = len(new_payload)
        diff = new_length - original_length
        print(f"[调试] 数据包 {packet_number}: 原始长度={original_length}, 新长度={new_length}, 差值={diff}")  # 新增调试信息

        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        if flow not in seq_diff:
            seq_diff[flow] = 0
        # 调整数值：原始序号加上累计偏移量
        pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
        # 更新累计偏移量
        seq_diff[flow] += diff

        pkt[Raw].load = new_payload

        # 删除校验和与长度字段，让 Scapy 自动重算
        if hasattr(pkt[IP], 'chksum'):
            del pkt[IP].chksum
        if hasattr(pkt[TCP], 'chksum'):
            del pkt[TCP].chksum
        if hasattr(pkt[IP], 'len'):
            del pkt[IP].len

        # 更新帧长度
        pkt.wirelen = len(pkt)  # 捕获到的帧总长度
        pkt.caplen = pkt.wirelen  # 捕获到的有效数据长度


# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"  # 输入 PCAP 文件路径
PCAP_OUT = "pcap/N16_modified116.pcap"  # 输出 PCAP 文件路径

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
    "ismfPduSessionUri": "http://200.20.20.26:80/nsmf-pdusession/v1/pdu-sessions/10000001"  # Updated ID
}

# 五元组 IP 替换内容
IP_REPLACEMENTS = {
    "200.20.20.26": "30.0.0.1",
    "200.20.20.25": "40.0.0.1"
}

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
print(f"[调试] 读取到 {len(packets)} 个数据包")  # 新增调试信息
modified_packets = []

# 保存每个流累计的 TCP 序号偏移量
seq_diff = {}

for i, pkt in enumerate(packets, 1):
    if TCP in pkt or Raw in pkt:
        print(f"\n[调试] ====== 开始处理第 {i} 个数据包 ======")  # 新增调试信息
        process_packet(pkt, MODIFICATIONS, seq_diff, IP_REPLACEMENTS, i)
        print(f"[调试] ====== 完成处理第 {i} 个数据包 ======")  # 新增调试信息
    else:
        print(f"[调试] 跳过数据包 {i} (不包含 TCP 或 Raw 层)")  # 新增调试信息
    modified_packets.append(pkt)

print(f"保存修改后的 PCAP 到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)
print("[调试] 脚本执行完成")  # 新增调试信息