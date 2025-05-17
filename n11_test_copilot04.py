from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re
import copy

# 配置参数
TARGET_FIELDS = {
    "supi": "imsi-460030100000022",
    "pei": "imeisv-1031014000012222",
    "gpsi": "msisdn-15910012222"
}
ORIGINAL_IMSI = "imsi-460030100000000"
MODIFIED_IMSI = "imsi-460030100000022"
PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_108.pcap"

MODIFY_PATH_PREFIX = "/nsmf-pdusession/v1/sm-contexts/"
MODIFY_PATH_SUFFIX = "-5/modify"
LOCATION_HEADER_PREFIX = "http://123.1.1.10/nsmf-pdusession/v1/sm-contexts/"
LOCATION_HEADER_SUFFIX = "-5"

# 可选：IP修改，若不需要可注释掉
CLIENT_IP_OLD = "121.1.1.10"
SERVER_IP_OLD = "123.1.1.10"
CLIENT_IP_NEW = "121.1.1.100"
SERVER_IP_NEW = "123.1.1.100"

class HTTP2FrameHeader(Packet):
    name = "HTTP2FrameHeader"
    fields_desc = [
        BitField("length", 0, 24),
        ByteField("type", 0),
        ByteField("flags", 0),
        BitField("reserved", 0, 1),
        BitField("stream_id", 0, 31)
    ]

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

def process_http2_headers_frame(frame_data, original_imsi, modified_imsi, pkt_idx=None, debug_print_49_path=False):
    """处理HTTP/2 HEADERS帧中的路径，location字段等。pkt_idx用于第49包特殊处理"""
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        new_headers = []
        modified = False
        for name, value in headers:
            # 特殊处理第49包
            if pkt_idx == 48 and name.lower() == ":path":
                if value.startswith(MODIFY_PATH_PREFIX) and value.endswith(MODIFY_PATH_SUFFIX):
                    mid = value[len(MODIFY_PATH_PREFIX):-len(MODIFY_PATH_SUFFIX)]
                    if mid.startswith("imsi-"):
                        new_value = MODIFY_PATH_PREFIX + modified_imsi + MODIFY_PATH_SUFFIX
                        print(f"[+] 修改第49包 :path 字段: {value} -> {new_value}")
                        new_headers.append((name, new_value))
                        modified = True
                        if debug_print_49_path:
                            print(f"*** [调试] 修改后第49包的path字段: {new_value}")
                    else:
                        new_headers.append((name, value))
                else:
                    new_headers.append((name, value))
            # 普通imsi路径替换
            elif name.lower() == ":path" and original_imsi in value:
                new_value = value.replace(original_imsi, modified_imsi)
                print(f"[+] 修改URL路径: {value} -> {new_value}")
                new_headers.append((name, new_value))
                modified = True
            # location字段imsi替换
            elif name.lower() == "location":
                if value.startswith(LOCATION_HEADER_PREFIX) and value.endswith(LOCATION_HEADER_SUFFIX):
                    mid = value[len(LOCATION_HEADER_PREFIX):-len(LOCATION_HEADER_SUFFIX)]
                    if mid.startswith("imsi-"):
                        new_value = LOCATION_HEADER_PREFIX + modified_imsi + LOCATION_HEADER_SUFFIX
                        print(f"[+] 修改Location字段: {value} -> {new_value}")
                        new_headers.append((name, new_value))
                        modified = True
                    else:
                        new_headers.append((name, value))
                else:
                    new_headers.append((name, value))
            else:
                new_headers.append((name, value))
        if modified:
            encoder = Encoder()
            new_data = encoder.encode(new_headers)
            return new_data
        return frame_data
    except Exception as e:
        print(f"HEADERS帧处理错误: {str(e)}")
        return frame_data

def modify_json_data(payload, fields):
    try:
        if not payload.strip():
            print("[跳过空数据段]")
            return None
        data = json.loads(payload)
        modified = False
        def recursive_modify(obj, modifications):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in obj.items():
                    lkey = key.lower()
                    for target in modifications:
                        if target.lower() == lkey:
                            print(f"[+] 修改JSON字段 {key} ({value}) -> {modifications[target]}")
                            obj[key] = modifications[target]
                            modified = True
                    if isinstance(value, (dict, list)):
                        recursive_modify(value, modifications)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        recursive_modify(item, modifications)
        recursive_modify(data, fields)
        return json.dumps(data, separators=(',', ':')).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def process_http2_data_frame(frame_data, fields):
    """处理HTTP/2 DATA帧中的多部分数据"""
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

def batch_collect_targets(original_packets):
    """
    缓存所有包的帧及可修改内容，只从原始pcap中提取，后续查找和定位都不再依赖修改后的数据。
    """
    pkt_http2_info = []
    for idx, pkt in enumerate(original_packets):
        pkt_info = []
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            frames = extract_http2_frames(raw)
            for fidx, frame in enumerate(frames):
                frame_type = frame['type']
                frame_data = frame['data']
                if frame_type == 0x1:  # HEADERS
                    pkt_info.append({
                        'frame_idx': fidx,
                        'type': 'headers',
                        'data': frame_data,
                        'frame': frame,
                    })
                elif frame_type == 0x0:  # DATA
                    pkt_info.append({
                        'frame_idx': fidx,
                        'type': 'data',
                        'data': frame_data,
                        'frame': frame,
                    })
        pkt_http2_info.append(pkt_info)
    return pkt_http2_info

def batch_modify_targets(pkt_http2_info, target_fields, original_imsi, modified_imsi):
    """
    所有修改都只在内存的工作区（深拷贝的包）操作，查找时只用原始缓存。
    """
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
                new_frame_data = process_http2_headers_frame(frame_data, original_imsi, modified_imsi, pkt_idx=pkt_idx)
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

def update_ip(pkt):
    """
    可选：根据需要修改IP地址。客户端和服务端IP地址修改建议双向对称。
    """
    if pkt.haslayer(IP):
        if pkt[IP].src == CLIENT_IP_OLD:
            pkt[IP].src = CLIENT_IP_NEW
        elif pkt[IP].src == SERVER_IP_OLD:
            pkt[IP].src = SERVER_IP_NEW
        if pkt[IP].dst == CLIENT_IP_OLD:
            pkt[IP].dst = CLIENT_IP_NEW
        elif pkt[IP].dst == SERVER_IP_OLD:
            pkt[IP].dst = SERVER_IP_NEW

def update_packets(original_packets, all_new_payloads):
    """
    工作区采用原始数据的深拷贝，所有修改都对拷贝进行，查找定位用原始数据。
    """
    seq_diff = {}
    modified_packets = []
    for idx, pkt in enumerate(original_packets):
        pkt = copy.deepcopy(pkt)
        update_ip(pkt)  # 可选：IP地址修改
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and all_new_payloads[idx]:
            flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            rev_flow = (pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport)
            seq_diff.setdefault(flow, 0)
            seq_diff.setdefault(rev_flow, 0)
            raw = bytes(pkt[Raw].load)
            new_payload = all_new_payloads[idx]
            diff = len(new_payload) - len(raw)
            pkt[Raw].load = new_payload
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]
            seq_diff[flow] += diff
            # 校验和、长度等清空交给scapy自动重算
            if hasattr(pkt[IP], 'chksum'):
                del pkt[IP].chksum
            if hasattr(pkt[TCP], 'chksum'):
                del pkt[TCP].chksum
            if hasattr(pkt[IP], 'len'):
                del pkt[IP].len
            pkt.wirelen = len(pkt)
            pkt.caplen = pkt.wirelen
        modified_packets.append(pkt)
    return modified_packets

if __name__ == "__main__":
    print(f"开始处理文件 {PCAP_IN}")
    # 1. 先读取原始pcap，缓存下来（全部操作都基于原始副本做查找定位）
    original_packets = rdpcap(PCAP_IN)
    # 2. 缓存所有HTTP2字段、内容信息
    pkt_http2_info = batch_collect_targets(original_packets)
    # 3. 统一批量修改，生成新payload
    all_new_payloads = batch_modify_targets(pkt_http2_info, TARGET_FIELDS, ORIGINAL_IMSI, MODIFIED_IMSI)
    # 4. 对原始包作深拷贝，所有修改都只作用于拷贝区（包括IP、TCP、payload等）
    new_packets = update_packets(original_packets, all_new_payloads)
    # 5. 输出新pcap
    print(f"保存修改到 {PCAP_OUT}")
    wrpcap(PCAP_OUT, new_packets)