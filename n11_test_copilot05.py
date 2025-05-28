from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re
import copy
from tqdm import tqdm

# 全局配置参数
sip1 = "40.0.0.1"
dip1 = "50.0.0.1"
auth1 = dip1
auth2 = sip1
imsi1 = "460012300000001"
imei14 = "86111010000001"
gpsi1 = "8613900000001"
PduAddr1 = "100.0.0.1"
dnn1 = "dnn600000001"
tac1 = "100001"
cgi1 = "010000001"
UpfIP1 = "80.0.0.1"
UpTeid1 = 0x70000001
UpfIP2 = "70.0.0.1"
UpTeid2 = 0x30000001
CLIENT_IP_OLD = "121.1.1.10"
SERVER_IP_OLD = "123.1.1.10"

# 示例：转换函数
def imei14_to_imeisv(imei14, sv="00"):
    """14位IMEI转16位IMEISV"""
    return imei14 + sv

# 示例：变量赋值
imei15 = imei14 + "0"
pei1 = imei14_to_imeisv(imei14, "00")  # 16位IMEISV

TARGET_FIELDS = {
    "supi": f"imsi-{imsi1}",
    "pei": f"imeisv-{pei1}",
    "gpsi": f"msisdn-{gpsi1}",
    "dnn": dnn1,
    "tac": tac1,
    "nrCellId": cgi1
}
ORIGINAL_IMSI = "imsi-460030100000000"
MODIFIED_IMSI = f"imsi-{imsi1}"

PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_1111.pcap"

# HTTP/2 帧解析函数
def extract_http2_frames(raw):
    offset = 0
    frames = []
    while offset < len(raw):
        if offset + 9 > len(raw):
            break
        frame_header = HTTP2FrameHeader(raw[offset:offset+9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        frame_end = offset + 9 + frame_len
        if frame_end > len(raw):
            frame_end = len(raw)
            frame_len = frame_end - (offset + 9)
            frame_header.length = frame_len
        frame_data = raw[offset+9:frame_end]
        frames.append({
            'offset': offset,
            'header': frame_header,
            'type': frame_type,
            'data': frame_data,
            'end': frame_end
        })
        offset = frame_end
    return frames

# 处理 HTTP/2 HEADERS 帧
def process_http2_headers_frame(frame_data, pkt_idx=None, new_content_length=None):
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        new_headers = []
        content_length_found = False

        for name, value in headers:
            # 替换 authority 字段
            if name.lower() == ":authority":
                if pkt_idx in [11, 48, 49]:
                    value = auth1
                elif pkt_idx == 46:
                    value = auth2
            # 替换 path 和 location 字段中的 IMSI
            if name.lower() in [":path", "location"]:
                value = re.sub(r'imsi-\d+', MODIFIED_IMSI, value)
            # 跳过旧的 content-length，后面会重新插入
            if name.lower() == "content-length":
                continue
            new_headers.append((name, value))

        # 插入新的 content-length
        if new_content_length is not None:
            new_headers.append(("content-length", str(new_content_length)))

        encoder = Encoder()
        return encoder.encode(new_headers)
    except Exception as e:
        print(f"[ERROR] 处理 HEADERS 帧失败: {e}")
        return frame_data

# 处理 HTTP/2 DATA 帧
def process_http2_data_frame(frame_data, fields):
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    segments = parts[i + 1].split(b"\r\n\r\n", 1)
                    if len(segments) == 2:
                        json_part = segments[1]
                        modified = modify_json_data(json_part, fields)
                        if modified:
                            parts[i + 1] = segments[0] + b"\r\n\r\n" + modified
        return b''.join(parts)
    else:
        modified = modify_json_data(frame_data, fields)
        return modified if modified else frame_data

# 修改 JSON 数据
def modify_json_data(payload, fields):
    try:
        data = json.loads(payload)
        modified = False

        def recursive_modify(obj, modifications):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in modifications:
                        obj[key] = modifications[key]
                        modified = True
                    elif isinstance(value, (dict, list)):
                        recursive_modify(value, modifications)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        recursive_modify(item, modifications)

        recursive_modify(data, fields)
        return json.dumps(data).encode() if modified else None
    except Exception as e:
        print(f"[ERROR] 修改 JSON 数据失败: {e}")
        return None

# 批量处理 HTTP/2 信息
def batch_modify_targets(pkt_http2_info, target_fields, original_imsi, modified_imsi):
    all_new_payloads = []
    for pkt_idx, pkt_info in enumerate(pkt_http2_info):
        if not pkt_info:
            all_new_payloads.append(None)
            continue

        new_frames = []
        for entry in pkt_info:
            frame = entry['frame']
            if entry['type'] == 'headers':
                frame_data = entry['data']
                new_frame_data = process_http2_headers_frame(frame_data, pkt_idx=pkt_idx)
                frame_header = frame['header']
                frame_header.length = len(new_frame_data)
                new_frames.append(frame_header.build() + new_frame_data)
            elif entry['type'] == 'data':
                frame_data = entry['data']
                new_frame_data = process_http2_data_frame(frame_data, target_fields)
                frame_header = frame['header']
                frame_header.length = len(new_frame_data)
                new_frames.append(frame_header.build() + new_frame_data)

        new_payload = b''.join(new_frames) if new_frames else None
        all_new_payloads.append(new_payload)

    return all_new_payloads

def batch_collect_targets(packets):
    """
    从数据包中提取 HTTP/2 信息。
    返回一个列表，每个元素是一个数据包的 HTTP/2 帧信息。
    """
    pkt_http2_info = []

    for pkt_idx, pkt in enumerate(packets):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            pkt_http2_info.append(None)
            continue

        raw_data = bytes(pkt[Raw].load)
        try:
            frames = extract_http2_frames(raw_data)
            pkt_info = []
            for frame in frames:
                frame_type = frame['type']
                if frame_type == 1:  # HEADERS 帧
                    pkt_info.append({
                        'type': 'headers',
                        'frame': frame,
                        'data': frame['data']
                    })
                elif frame_type == 0:  # DATA 帧
                    pkt_info.append({
                        'type': 'data',
                        'frame': frame,
                        'data': frame['data']
                    })
            pkt_http2_info.append(pkt_info if pkt_info else None)
        except Exception as e:
            print(f"[ERROR] 提取第 {pkt_idx} 个数据包的 HTTP/2 信息失败: {e}")
            pkt_http2_info.append(None)

    return pkt_http2_info

# 更新 IP 地址
def update_ip(pkt):
    if pkt.haslayer(IP):
        if pkt[IP].src == CLIENT_IP_OLD:
            pkt[IP].src = sip1
        elif pkt[IP].src == SERVER_IP_OLD:
            pkt[IP].src = dip1
        if pkt[IP].dst == CLIENT_IP_OLD:
            pkt[IP].dst = sip1
        elif pkt[IP].dst == SERVER_IP_OLD:
            pkt[IP].dst = dip1

# 更新数据包
def update_packets(original_packets, all_new_payloads):
    seq_diff = {}
    modified_packets = []

    for idx, pkt in enumerate(original_packets):
        pkt = copy.deepcopy(pkt)
        update_ip(pkt)

        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and all_new_payloads[idx]:
            raw = bytes(pkt[Raw].load)
            new_payload = all_new_payloads[idx]
            diff = len(new_payload) - len(raw)
            pkt[Raw].load = new_payload

            flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            rev_flow = (pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport)

            seq_diff.setdefault(flow, 0)
            seq_diff.setdefault(rev_flow, 0)
            pkt[TCP].seq += seq_diff[flow]

            if pkt[TCP].flags & 0x10:  # ACK flag
                pkt[TCP].ack += seq_diff[rev_flow]

            seq_diff[flow] += diff
            del pkt[IP].chksum
            del pkt[TCP].chksum

        modified_packets.append(pkt)

    return modified_packets

if __name__ == "__main__":
    original_packets = rdpcap(PCAP_IN)
    pkt_http2_info = batch_collect_targets(original_packets)  # 提取 HTTP/2 信息
    all_new_payloads = batch_modify_targets(pkt_http2_info, TARGET_FIELDS, ORIGINAL_IMSI, MODIFIED_IMSI)
    new_packets = update_packets(original_packets, all_new_payloads)
    wrpcap(PCAP_OUT, new_packets)