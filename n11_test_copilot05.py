from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re
import copy
from tqdm import tqdm

# 全局配置参数（只保留一份）
sip1 = "40.0.0.1"
dip1 = "50.0.0.1"
auth1 = dip1
auth2 = sip1
imsi1 = "460012300000001"
imei14 = "86111010000001"  # 14位IMEI初始值
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

def luhn_checksum(numstr):
    """计算Luhn校验和（用于IMEI第15位）"""
    digits = [int(d) for d in numstr]
    oddsum = sum(digits[-1::-2])
    evensum = sum([sum(divmod(2 * d, 10)) for d in digits[-2::-2]])
    return (oddsum + evensum) % 10

def imei14_to_imei15(imei14):
    """14位IMEI转15位IMEI（加Luhn校验）"""
    check = luhn_checksum(imei14 + '0')
    check_digit = (10 - check) % 10
    return imei14 + str(check_digit)

def imei14_to_imeisv(imei14, sv="00"):
    """14位IMEI转16位IMEISV"""
    return imei14 + sv

# 示例：变量赋值
imei14 = "86111010000001"
imei15 = imei14_to_imei15(imei14)
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
MODIFIED_IMSI = "imsi-460030100000022"

PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_1103.pcap"

MODIFY_PATH_PREFIX = "/nsmf-pdusession/v1/sm-contexts/"
MODIFY_PATH_SUFFIX = "-5/modify"
LOCATION_HEADER_PREFIX = "http://123.1.1.10/nsmf-pdusession/v1/sm-contexts/"
LOCATION_HEADER_SUFFIX = "-5"


# 递增函数
def inc_ip(ip, step=1):
    parts = list(map(int, ip.split('.')))
    val = (parts[0]<<24) + (parts[1]<<16) + (parts[2]<<8) + parts[3] + step
    return f"{(val>>24)&0xFF}.{(val>>16)&0xFF}.{(val>>8)&0xFF}.{val&0xFF}"

def inc_int(val, step=1):
    return str(int(val) + step)

def inc_hex(val, step=1):
    return val + step

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

def process_http2_headers_frame(frame_data, pkt_idx=None, new_content_length=None):
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        new_headers = []
        modified = False
        # 1. 先移除所有content-length
        for name, value in headers:
            if name.lower() == "content-length":
                print(f"[DEBUG] 移除原有content-length: {value}")
                continue
            # 其它字段正常处理
            if pkt_idx == 11 and name.lower() == ":authority":
                print(f"[DEBUG] 替换 authority: {value} -> {auth1}")
                value = auth1
                modified = True
            if pkt_idx == 45 and name.lower() == "location":
                value = value.replace("123.1.1.10", auth1)
                modified = True
            if pkt_idx == 46 and name.lower() == ":authority":
                print(f"[DEBUG] 替换 authority: {value} -> {auth2}")
                value = auth2
                modified = True
            if pkt_idx == 48 and name.lower() == ":authority":
                value = auth1
                modified = True
            if pkt_idx == 46 and name.lower() == ":path":
                value = re.sub(r'imsi-\d+', f'imsi-{imsi1}', value)
                modified = True
            if pkt_idx == 48 and name.lower() == ":path":
                value = re.sub(r'imsi-\d+', f'imsi-{imsi1}', value)
                modified = True
            new_headers.append((name, value))
        # 2. 最后插入一个新的content-length
        if new_content_length is not None:
            print(f"[DEBUG] 插入新的content-length: {new_content_length}")
            new_headers.append(("content-length", str(new_content_length)))
        encoder = Encoder()
        new_data = encoder.encode(new_headers)
        return new_data
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

def update_packets(original_packets, all_new_payloads):
    seq_diff = {}
    modified_packets = []
    for idx, pkt in enumerate(original_packets):
        pkt = copy.deepcopy(pkt)
        update_ip(pkt)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and all_new_payloads[idx]:
            flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            rev_flow = (pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport)
            seq_diff.setdefault(flow, 0)
            seq_diff.setdefault(rev_flow, 0)
            raw = bytes(pkt[Raw].load)
            new_payload = all_new_payloads[idx]
            diff = len(new_payload) - len(raw)
            pkt[Raw].load = new_payload
            # 统一用累计diff表调整seq/ack
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]
            seq_diff[flow] += diff
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
    original_packets = rdpcap(PCAP_IN)
    pkt_http2_info = batch_collect_targets(original_packets)
    all_new_payloads = batch_modify_targets(pkt_http2_info, TARGET_FIELDS, ORIGINAL_IMSI, MODIFIED_IMSI)
    # 只保留一种主循环处理方式
    new_packets = update_packets(original_packets, all_new_payloads)
    print(f"保存修改到 {PCAP_OUT}")
    wrpcap(PCAP_OUT, new_packets)