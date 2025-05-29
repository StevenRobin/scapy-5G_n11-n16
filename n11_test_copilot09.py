from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap, rdpcap
from scapy.layers.l2 import Ether
from scapy.all import Raw
from hpack import Encoder, Decoder
import json
import re
import copy
from tqdm import tqdm
from typing import Dict, Any, List, Optional
import os
import concurrent.futures
from collections import defaultdict

# 全局配置参数
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

SV_DEFAULT = "00"
RE_IMSI = re.compile(r'imsi-\d+')

def luhn_checksum(numstr: str) -> int:
    """计算Luhn校验和（用于IMEI第15位）"""
    digits = [int(d) for d in numstr]
    oddsum = sum(digits[-1::-2])
    evensum = sum(sum(divmod(2 * d, 10)) for d in digits[-2::-2])
    return (oddsum + evensum) % 10

def imei14_to_imei15(imei14: str) -> str:
    """14位IMEI转15位IMEI（加Luhn校验）"""
    check = luhn_checksum(imei14 + '0')
    check_digit = (10 - check) % 10
    return imei14 + str(check_digit)

def imei14_to_imeisv(imei14: str, sv: str = SV_DEFAULT) -> str:
    """14位IMEI转16位IMEISV"""
    return imei14 + sv

# 示例变量赋值（去除重复）
imei15 = imei14_to_imei15(imei14)
pei1 = imei14_to_imeisv(imei14)

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

PCAP_IN = "pcap/N11_create_50p_portX.pcap"
PCAP_OUT = "pcap/N11_1w_01.pcap"

MODIFY_PATH_PREFIX = "/nsmf-pdusession/v1/sm-contexts/"
MODIFY_PATH_SUFFIX = "-5/modify"
LOCATION_HEADER_PREFIX = "http://123.1.1.10/nsmf-pdusession/v1/sm-contexts/"
LOCATION_HEADER_SUFFIX = "-5"

def inc_ip(ip: str, step: int = 1) -> str:
    parts = list(map(int, ip.split('.')))
    val = (parts[0]<<24) + (parts[1]<<16) + (parts[2]<<8) + parts[3] + step
    return f"{(val>>24)&0xFF}.{(val>>16)&0xFF}.{(val>>8)&0xFF}.{val&0xFF}"

def get_ip_pair(base_sip, base_dip, idx, ip_num=1000):
    sip = inc_ip(base_sip, idx % ip_num)
    dip = inc_ip(base_dip, idx % ip_num)
    return sip, dip

def inc_int(val: str, step: int = 1) -> str:
    return str(int(val) + step)

def inc_hex(val: int, step: int = 1) -> int:
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

def extract_http2_frames(raw: bytes) -> List[Dict[str, Any]]:
    """提取HTTP2帧"""
    offset = 0
    frames = []
    while offset + 9 <= len(raw):
        frame_header = HTTP2FrameHeader(raw[offset:offset+9])
        frame_len = frame_header.length
        frame_end = min(offset + 9 + frame_len, len(raw))
        frame_data = raw[offset+9:frame_end]
        frames.append({
            'offset': offset,
            'header': frame_header,
            'type': frame_header.type,
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
        for name, value in headers:
            if name.lower() == "content-length":
                print(f"[DEBUG] 移除原有content-length: {value}")
                continue
            orig_type = type(value)
            # 其它字段正常处理
            if pkt_idx == 11 and name.lower() == ":authority":
                print(f"[DEBUG] 替换 authority: {value} -> {auth1}")
                value = auth1
                modified = True
            if pkt_idx == 45 and name.lower() == "location":
                # 兼容bytes/bytearray/memoryview
                if isinstance(value, (bytes, bytearray, memoryview)):
                    value = value.tobytes() if isinstance(value, memoryview) else bytes(value)
                    value = value.decode(errors='ignore')
                value = str(value).replace("123.1.1.10", auth1)
                modified = True
                if orig_type in (bytes, bytearray, memoryview):
                    value = value.encode()
            if pkt_idx == 46 and name.lower() == ":authority":
                print(f"[DEBUG] 替换 authority: {value} -> {auth2}")
                value = auth2
                modified = True
            if pkt_idx == 48 and name.lower() == ":authority":
                value = auth1
                modified = True
            if pkt_idx == 46 and name.lower() == ":path":
                if isinstance(value, (bytes, bytearray, memoryview)):
                    value = value.tobytes() if isinstance(value, memoryview) else bytes(value)
                    value = value.decode(errors='ignore')
                value = re.sub(r'imsi-\d+', f'imsi-{imsi1}', str(value))
                modified = True
                if orig_type in (bytes, bytearray, memoryview):
                    value = value.encode()
            if pkt_idx == 48 and name.lower() == ":path":
                if isinstance(value, (bytes, bytearray, memoryview)):
                    value = value.tobytes() if isinstance(value, memoryview) else bytes(value)
                    value = value.decode(errors='ignore')
                value = re.sub(r'imsi-\d+', f'imsi-{imsi1}', str(value))
                modified = True
                if orig_type in (bytes, bytearray, memoryview):
                    value = value.encode()
            new_headers.append((name, value))
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
        if not payload or not payload.strip():
            return payload
        try:
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8')
            else:
                payload_str = payload
        except UnicodeDecodeError:
            payload_str = payload
        data = json.loads(payload_str)
        modified = False
        def recursive_modify(obj):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in list(obj.items()):
                    # 1. 目标字段直接替换
                    for target in fields:
                        if key.lower() == target.lower():
                            if value != fields[target]:
                                print(f"[JSON修改] {key}: {value} -> {fields[target]}")
                                obj[key] = fields[target]
                                modified = True
                    # 2. smContextStatusUri特殊处理
                    if key == "smContextStatusUri" and isinstance(value, str):
                        # 替换host部分为sip1
                        new_val = re.sub(r"(?<=://)[^/:]+", sip1, value)
                        if value != new_val:
                            print(f"[JSON修改] smContextStatusUri: {value} -> {new_val}")
                            obj[key] = new_val
                            modified = True
                    if isinstance(value, (dict, list)):
                        recursive_modify(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        recursive_modify(item)
        recursive_modify(data)
        if modified:
            return json.dumps(data, indent=None, separators=(',', ':')).encode()
        else:
            return payload
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return payload

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
        # 先处理DATA帧，拿到新内容长度
        new_content_length = None
        data_frame_new_data = None
        for entry in pkt_info:
            if entry['type'] == 'data':
                # 关键报文DATA帧精确处理
                if pkt_idx in (46, 48):
                    data_frame_new_data = process_http2_data_frame_precise(pkt_idx, entry['data'], target_fields)
                else:
                    data_frame_new_data = process_http2_data_frame(entry['data'], target_fields)
                new_content_length = len(data_frame_new_data)
                entry['__new_data'] = data_frame_new_data
        for entry in pkt_info:
            frame = entry['frame']
            if entry['type'] == 'headers':
                # 关键报文严格重建
                if pkt_idx in (11, 45, 46, 48):
                    new_frame_data = process_http2_headers_frame_precise(pkt_idx, new_content_length)
                    if new_frame_data is None:
                        new_frame_data = process_http2_headers_frame(entry['data'], pkt_idx=pkt_idx, new_content_length=new_content_length)
                else:
                    new_frame_data = process_http2_headers_frame(entry['data'], pkt_idx=pkt_idx, new_content_length=new_content_length)
                frame_header = frame['header']
                frame_header.length = len(new_frame_data)
                new_frames.append(frame_header.build() + new_frame_data)
            elif entry['type'] == 'data':
                # 直接用已处理的新DATA帧内容
                if '__new_data' in entry:
                    new_frame_data = entry['__new_data']
                else:
                    new_frame_data = process_http2_data_frame(entry['data'], target_fields)
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

def update_packets(original_packets, all_new_payloads, sip, dip, orig2new_sport):
    """
    用累计diff递推法修正TCP seq/ack，兼容多IP/端口分配。
    """
    seq_diff = {}
    modified_packets = []
    for idx, pkt in enumerate(original_packets):
        pkt = copy.deepcopy(pkt)
        # IP替换
        if pkt.haslayer(IP):
            if pkt[IP].src == CLIENT_IP_OLD:
                pkt[IP].src = sip
            elif pkt[IP].src == SERVER_IP_OLD:
                pkt[IP].src = dip
            if pkt[IP].dst == CLIENT_IP_OLD:
                pkt[IP].dst = sip
            elif pkt[IP].dst == SERVER_IP_OLD:
                pkt[IP].dst = dip
        # sport替换
        if pkt.haslayer(TCP):
            key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            pkt[TCP].sport = orig2new_sport.get(key, pkt[TCP].sport)
        # 累计diff递推
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and all_new_payloads and all_new_payloads[idx]:
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

def process_http2_headers_frame_precise(pkt_idx, new_content_length=None):
    """
    针对关键报文（12、46、47、49）严格重建HTTP/2头部，顺序和内容100%准确。
    """
    encoder = Encoder()
    # 12、46、47、49为Wireshark序号，Python下从0计数，需-1
    if pkt_idx == 11:  # 第12个报文
        headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", auth1),
            (":path", "/nsmf-pdusession/v1/sm-contexts"),
            ("content-type", "application/json"),
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("accept", "application/json"),
            ("user-agent", "AMF"),  # 保持原始值AMF
        ]
        print(f"[精确重建] pkt12 HEADERS: {headers}")
        return encoder.encode(headers)
    elif pkt_idx == 45:  # 第46个报文
        headers = [
            (":status", "201"),
            ("content-type", "application/json"),
            ("location", f"http://{auth1}/nsmf-pdusession/v1/sm-contexts/{imsi1}-5"),
            ("date", "Wed, 22 May 2025 02:48:05 GMT"),
            ("content-length", str(new_content_length) if new_content_length else "0"),
        ]
        print(f"[精确重建] pkt46 HEADERS: {headers}")
        return encoder.encode(headers)
    elif pkt_idx == 46:  # 第47个报文
        headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", auth2),
            (":path", f"/namf-comm/v1/ue-contexts/imsi-{imsi1}/n1-n2-messages"),
            ("content-type", "application/json"),
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("user-agent", "SMF"),  # 保持原始值SMF，无accept字段
        ]
        print(f"[精确重建] pkt47 HEADERS: {headers}")
        return encoder.encode(headers)
    elif pkt_idx == 48:  # 第49个报文
        headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", auth1),
            (":path", f"/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify"),
            ("content-type", "application/json"),
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("accept", "application/json"),
            ("user-agent", "SMF"),  # 保持原始值SMF
        ]
        print(f"[精确重建] pkt49 HEADERS: {headers}")
        return encoder.encode(headers)
    else:
        return None

def process_http2_data_frame_precise(pkt_idx, frame_data, fields):
    """
    针对关键报文（47、49）DATA帧，精确替换gTPTunnel、DNN、PduAddr等二进制字段。
    这里只做结构，具体二进制替换可后续细化。
    """
    # 这里只做调试输出，实际可按需求补充二进制替换
    if pkt_idx in (46, 48):
        print(f"[精确重建] pkt{pkt_idx+1} DATA帧处理，原始长度: {len(frame_data)}")
        # TODO: 按需实现gTPTunnel、DNN、PduAddr等字段的二进制替换
        # 可参考n16_batch16_1000ip_perf.py的apply_direct_binary_replacements等
        # 这里只返回原始数据
        return frame_data
    else:
        return frame_data

def build_orig2new_sport(original_packets, start_port=10001):
    """为每个五元组分配唯一新sport端口"""
    orig2new_sport = {}
    next_port = start_port
    for pkt in original_packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            if key not in orig2new_sport:
                orig2new_sport[key] = next_port
                next_port += 1
    return orig2new_sport

def process_one_batch(original_packets, batch_idx, base_sip, base_dip, orig2new_sport, ip_num=1000, target_fields=None, original_imsi=None, modified_imsi=None):
    sip, dip = get_ip_pair(base_sip, base_dip, batch_idx, ip_num)
    # 1. 提取HTTP2帧
    pkt_http2_info = batch_collect_targets(original_packets)
    # 2. 修改payload
    all_new_payloads = batch_modify_targets(pkt_http2_info, target_fields, original_imsi, modified_imsi)
    # 3. 替换IP、端口、payload
    new_packets = update_packets(original_packets, all_new_payloads, sip, dip, orig2new_sport)
    return new_packets

def main_batch(
    pcap_in=PCAP_IN,
    pcap_out=PCAP_OUT,
    loop_num=1,
    batch_size=50,
    ip_num=1000
):
    print(f"开始批量处理文件 {pcap_in}")
    original_packets = rdpcap(pcap_in)
    orig2new_sport = build_orig2new_sport(original_packets)
    total_batches = (loop_num + batch_size - 1) // batch_size
    base_sip = "40.0.0.1"
    base_dip = "50.0.0.1"
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for batch_idx in range(total_batches):
            futures.append(executor.submit(
                process_one_batch, original_packets, batch_idx, base_sip, base_dip, orig2new_sport, ip_num
            ))
        for batch_idx, f in enumerate(tqdm(concurrent.futures.as_completed(futures), total=total_batches)):
            batch_packets = f.result()
            out_file = f"{pcap_out[:-5]}_{batch_idx+1:03d}.pcap"
            wrpcap(out_file, batch_packets)
            del batch_packets
    print("全部批量处理完成。")

if __name__ == "__main__":
    main_batch(
        pcap_in=PCAP_IN,
        pcap_out=PCAP_OUT,
        loop_num=1000,  # 可根据需要调整
        batch_size=1000,
        ip_num=1000
    )
