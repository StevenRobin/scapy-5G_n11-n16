from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re
import os
import concurrent.futures
from tqdm import tqdm
import gc
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import random
import hashlib

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
    try:
        if offset + 9 > len(raw):
            return None, None, None, None, len(raw)
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        frame_end = offset + 9 + frame_len
        if frame_end > len(raw):
            frame_end = len(raw)
            frame_len = frame_end - (offset + 9)
            frame_header.length = frame_len
        frame_data = raw[offset + 9:frame_end]
        return frame_header, frame_len, frame_type, frame_data, frame_end
    except Exception:
        return None, None, None, None, len(raw)

def modify_json_data(payload):
    try:
        if not payload.strip():
            return None
        try:
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8')
            else:
                payload_str = payload
        except UnicodeDecodeError:
            payload_str = payload
        data = json.loads(payload_str)
        modified = False
        var_map = JSON_FIELD_MAP
        def recursive_modify(obj):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in list(obj.items()):
                    if key == "ismfId":
                        parts = value.rsplit("-", 1)
                        if len(parts) == 2:
                            new_val = f"{parts[0]}-{ismfId1}"
                            if value != new_val:
                                obj[key] = new_val
                                modified = True
                    elif key == "ismfPduSessionUri":
                        m = re.match(r"http://([\d.]+):\d+/(.+/)(\d+)", value)
                        if m:
                            new_val = f"http://{sip1}/{m.group(2)}{pduSessionId1}"
                            if value != new_val:
                                obj[key] = new_val
                                modified = True
                    elif key in var_map and var_map[key] is not None:
                        if value != var_map[key]:
                            obj[key] = var_map[key]
                            modified = True
                    elif key in ["icnTunnelInfo", "cnTunnelInfo"] and isinstance(value, dict):
                        for subk in ["ipv4Addr", "gtpTeid"]:
                            if subk in value and value.get(subk) != var_map[key][subk]:
                                value[subk] = var_map[key][subk]
                                modified = True
                    elif isinstance(value, (dict, list)):
                        recursive_modify(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        recursive_modify(item)
        recursive_modify(data)
        if modified:
            return json.dumps(data, indent=None, separators=(',', ':')).encode()
        else:
            return None
    except Exception:
        return None

def process_http2_data_frame(frame_data):
    if not frame_data:
        return frame_data
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    segments = parts[i + 1].split(b"\r\n\r\n", 1)
                    if len(segments) == 2:
                        json_part = segments[1]
                        modified = modify_json_data(json_part)
                        if modified:
                            parts[i + 1] = segments[0] + b"\r\n\r\n" + modified
        return b''.join(parts)
    else:
        try:
            modified = modify_json_data(frame_data)
            return modified if modified else frame_data
        except Exception:
            return frame_data

def process_packet(pkt, seq_diff, ip_replacements, original_length=None, new_length=None):
    if pkt.haslayer(IP):
        if pkt[IP].src in ip_replacements:
            pkt[IP].src = ip_replacements[pkt[IP].src]
        if pkt[IP].dst in ip_replacements:
            pkt[IP].dst = ip_replacements[pkt[IP].dst]
    if pkt.haslayer(TCP):
        # 上行：源IP为sip1，源端口设为sport1
        if pkt[IP].src == sip1:
            pkt[TCP].sport = sport1
        # 下行：源IP为dip1，目的端口设为sport1
        if pkt[IP].src == dip1:
            pkt[TCP].dport = sport1
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
        if original_length is not None and new_length is not None:
            diff = new_length - original_length
        if has_payload and not (is_syn or is_fin or is_rst):
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]
            seq_diff[flow] += diff
        else:
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]
        if hasattr(pkt[IP], 'chksum'):
            del pkt[IP].chksum
        if hasattr(pkt[TCP], 'chksum'):
            del pkt[TCP].chksum
        if hasattr(pkt[IP], 'len'):
            del pkt[IP].len
        pkt.wirelen = len(pkt)
        pkt.caplen = pkt.wirelen

def process_special_headers(frame_data, pkt_idx, data_length=None):
    try:
        if pkt_idx == 15:
            try:
                fixed_headers = [
                    (b':status', b'201'),
                    (b'content-type', b'application/json'),
                    (b'location', f"http://{auth1}/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()),
                    (b'date', b'Wed, 22 May 2025 02:48:05 GMT'),
                    (b'content-length', b'351')
                ]
                encoder = Encoder()
                new_headers_data = encoder.encode(fixed_headers)
                return new_headers_data
            except Exception:
                return frame_data
        if pkt_idx in {9, 13}:
            try:
                headers = [
                    (b':method', b'POST'),
                    (b':scheme', b'http'),
                    (b':authority', auth1.encode()),
                    (b':path', b'/nsmf-pdusession/v1/pdu-sessions')
                ]
                headers.append((b'content-type', b'application/json'))
                if data_length is not None:
                    headers.append((b'content-length', str(data_length).encode()))
                else:
                    headers.append((b'content-length', b'0'))
                headers.append((b'accept', b'application/json'))
                encoder = Encoder()
                new_data = encoder.encode(headers)
                return new_data
            except Exception:
                return frame_data
        elif pkt_idx == 11:
            return frame_data
        else:
            try:
                decoder = Decoder()
                headers = decoder.decode(frame_data)
                encoder = Encoder()
                return encoder.encode(headers)
            except Exception:
                return frame_data
    except Exception:
        return frame_data

def update_content_length(headers_data, body_length):
    try:
        decoder = Decoder()
        encoder = Encoder()
        headers = decoder.decode(headers_data)
        modified = False
        new_headers = []
        for name, value in headers:
            name_str = name.decode() if isinstance(name, bytes) else name
            if name_str.lower() == "content-length":
                if isinstance(value, bytes):
                    new_headers.append((name, str(body_length).encode()))
                else:
                    new_headers.append((name, str(body_length)))
                modified = True
            else:
                new_headers.append((name, value))
        if not modified:
            content_length_key = "content-length"
            content_length_value = str(body_length)
            if any(isinstance(name, bytes) for name, _ in headers):
                content_length_key = b"content-length"
            if any(isinstance(value, bytes) for _, value in headers):
                content_length_value = str(body_length).encode()
            new_headers.append((content_length_key, content_length_value))
        new_headers_data = encoder.encode(new_headers)
        return new_headers_data
    except Exception:
        return headers_data

def extract_frames(raw_data):
    frames = []
    offset = 0
    while offset < len(raw_data):
        frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw_data, offset)
        if frame_header is None or frame_data is None:
            break
        frames.append((frame_header, frame_type, frame_data, offset, frame_end))
        offset = frame_end
    return frames

def apply_direct_binary_replacements(pkt, idx):
    if not pkt.haslayer(Raw):
        return False
    modified = False
    load = bytes(pkt[Raw].load)
    ip_replacements = [
        (b'200.20.20.25:8080', f"{auth1}".encode()),
        (b'200.20.20.25', auth1.encode()),
        (bytes([0x32, 0x30, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x35]), auth1.encode()),
    ]
    if idx in {9, 11, 13}:
        authority_replacements = []
        auth_patterns = [
            b':authority:', b':authority: ',
            b'authority:', b'authority: '
        ]
        for pattern in auth_patterns:
            pos = load.find(pattern)
            if pos >= 0:
                val_start = pos + len(pattern)
                val_end = val_start
                for end_char in [b'\r', b'\n', b';', b':', b' ']:
                    next_pos = load.find(end_char, val_start)
                    if next_pos > 0 and (val_end == val_start or next_pos < val_end):
                        val_end = next_pos
                if val_end == val_start:
                    val_end = min(val_start + 30, len(load))
                current_val = load[val_start:val_end]
                if current_val and current_val != auth1.encode():
                    full_pattern = pattern + current_val
                    full_replacement = pattern + auth1.encode()
                    authority_replacements.append((full_pattern, full_replacement))
        ip_replacements.extend(authority_replacements)
    if idx == 15:
        location_patterns = []
        loc_headers = [b'location:', b'Location:', b'location :', b'Location :']
        for header in loc_headers:
            pos = load.find(header)
            if pos >= 0:
                val_start = pos + len(header)
                val_end = -1
                for end_mark in [b'\r\n', b'\n', b';', b':']:
                    next_pos = load.find(end_mark, val_start)
                    if next_pos > 0 and (val_end < 0 or next_pos < val_end):
                        val_end = next_pos
                if val_end < 0:
                    val_end = len(load)
                uri_val = load[val_start:val_end].strip()
                if uri_val and b'http://' in uri_val:
                    new_uri = f"http://{sip1}/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()
                    location_patterns.append((header + b' ' + uri_val, header + b' ' + new_uri))
        url_patterns = [
            rb'http://[\d\.]+(?::\d+)?/nsmf-pdusession/v1/pdu-sessions/\d+',
            rb'/nsmf-pdusession/v1/pdu-sessions/\d+'
        ]
        for pattern_str in url_patterns:
            pattern = re.compile(pattern_str)
            for match in pattern.finditer(load):
                old_url = match.group(0)
                if b'/pdu-sessions/' in old_url:
                    if b'http://' in old_url:
                        new_url = f"http://{sip1}/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()
                    else:
                        new_url = f"/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()
                    location_patterns.append((old_url, new_url))
        ip_replacements.extend(location_patterns)
    for pattern, replacement in ip_replacements:
        if pattern in load:
            new_load = load.replace(pattern, replacement)
            if new_load != load:
                modified = True
                load = new_load
    path_pattern = re.compile(br'/nsmf-pdusession/v1/sm-contexts/(\d+)')
    for match in path_pattern.finditer(load):
        old_id = match.group(1)
        if old_id != context_ID.encode():
            new_load = load.replace(
                match.group(0),
                f"/nsmf-pdusession/v1/sm-contexts/{context_ID}".encode()
            )
            if new_load != load:
                modified = True
                load = new_load
    if idx == 15:
        session_pattern = re.compile(br'/pdu-sessions/(\d+)')
        for match in session_pattern.finditer(load):
            old_id = match.group(1)
            if old_id != context_ID.encode():
                new_load = load.replace(
                    match.group(0),
                    f"/pdu-sessions/{context_ID}".encode()
                )
                if new_load != load:
                    modified = True
                    load = new_load
    if modified:
        pkt[Raw].load = load
    return modified

def inc_ip(ip, step=1):
    parts = list(map(int, ip.split('.')))
    val = (parts[0]<<24) + (parts[1]<<16) + (parts[2]<<8) + parts[3] + step
    return f"{(val>>24)&0xFF}.{(val>>16)&0xFF}.{(val>>8)&0xFF}.{val&0xFF}"

def inc_int(val, step=1):
    return str(int(val) + step)

def inc_hex(val, step=1, width=None):
    v = int(val, 16) + step
    if width is None:
        width = len(val)
    return f"{v:0{width}X}"

def inc_imei15(val, step=1):
    """15位IMEI整体递增，保持15位，不足补0"""
    v = int(val)
    v += step
    return f"{v:015d}"

def calculate_sv_for_continuous_imei(imei15: str) -> str:
    """
    计算适当的SV值，使得从IMEISV反推出来的IMEI与预期的imei15相同
    
    关键思路：
    1. 从目标IMEI（15位）取前14位
    2. 计算Luhn校验位（这是标准IMEI的第15位）
    3. 如果目标IMEI的第15位就等于计算出的Luhn校验位，SV="00"
    4. 如果不等于，需要特殊处理，将SV值设置为使得反推IMEI时能得到目标IMEI
    """
    imei14 = imei15[:14]
    # 计算标准Luhn校验码
    def calculate_luhn(digits):
        total = 0
        for i, d in enumerate(digits):
            d = int(d)
            # 偶数位（从0开始）乘2
            if i % 2 == 1:  # 从右往左是偶数位，从左往右就是奇数索引
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return (10 - (total % 10)) % 10
    
    # 计算标准校验码
    standard_check = calculate_luhn(imei14)
    # 目标IMEI的实际校验码（第15位）
    actual_check = int(imei15[14])
    
    # 如果标准校验码等于目标校验码，使用常规SV值"00"
    if standard_check == actual_check:
        return "00"
    else:
        # 否则，使用特殊SV值，保持递增特性
        # 这里用实际校验码作为SV的十位数，0作为个位数
        # 这样可以通过SV值反推原始校验码
        return f"{actual_check}0"

def imei2imeisv(imei15: str) -> str:
    """
    根据15位IMEI转换为16位IMEISV。
    计算特殊SV使IMEISV反推IMEI时保持递增
    """
    sv = calculate_sv_for_continuous_imei(imei15)
    return imei15[:14] + sv

def imeisv_to_imei(imeisv: str) -> str:
    """
    16位IMEISV转15位IMEI（Luhn校验码）
    """
    imei14 = imeisv[:14]
    # Luhn算法
    def luhn(digits):
        total = 0
        for i, d in enumerate(digits):
            d = int(d)
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return (10 - (total % 10)) % 10
    check = luhn(imei14)
    return imei14 + str(check)

def inc_imei14(val, step=1):
    """14位IMEI递增，保持14位，不足补0"""
    v = int(val)
    v += step
    return f"{v:014d}"

def imei14_to_imei15(imei14: str) -> str:
    """14位IMEI转15位IMEI（自动加Luhn校验码）"""
    def luhn(digits):
        total = 0
        for i, d in enumerate(digits):
            d = int(d)
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return (10 - (total % 10)) % 10
    check = luhn(imei14)
    return imei14 + str(check)

def imei14_to_imeisv(imei14: str, sv: str = "00") -> str:
    """14位IMEI转16位IMEISV（+SV）"""
    return imei14 + sv

def update_global_vars(i, ip_num=1000):
    global auth1, context_ID, imsi1, pei1, gpsi1, dnn1, ismfId1, upf1, teid1, upf2, teid2, ueIP1, tac1, cgi1, pduSessionId1, sip1, dip1, sport1
    base = {
        "auth1": "40.0.0.1",
        "context_ID": "9000000001",
        "imsi1": "460012300000001",
        "imei14": "86111010000001",  # 14位IMEI初始值
        "gpsi1": "8613900000001",
        "dnn1": "dnn600000001",
        "ismfId1": "000500000001",
        "upf1": "10.0.0.1",
        "teid1": "10000001",
        "upf2": "20.0.0.1",
        "teid2": "50000001",
        "ueIP1": "100.0.0.1",
        "tac1": "100001",
        "cgi1": "010000001",
        "pduSessionId1": "10000001",
        "sip1": "30.0.0.1",
        "dip1": "40.0.0.1"
    }
    auth1 = inc_ip(base["auth1"], i)
    context_ID = inc_int(base["context_ID"], i)
    imsi1 = inc_int(base["imsi1"], i)
    imei14 = inc_imei14(base["imei14"], i)         # 14位IMEI递增
    imei15 = imei14_to_imei15(imei14)              # 15位IMEI（自动加Luhn）
    pei1 = imei14_to_imeisv(imei14, "00")          # 16位IMEISV
    gpsi1 = inc_int(base["gpsi1"], i)
    dnn1 = "dnn" + inc_int(base["dnn1"][3:], i)
    ismfId1 = inc_int(base["ismfId1"], i)
    upf1 = inc_ip(base["upf1"], i)
    teid1 = inc_hex(base["teid1"], i, width=len(base["teid1"]))   # 按hex递增
    upf2 = inc_ip(base["upf2"], i)
    teid2 = inc_hex(base["teid2"], i, width=len(base["teid2"]))   # 按hex递增
    ueIP1 = inc_ip(base["ueIP1"], i)
    tac1 = inc_hex(base["tac1"], i, width=len(base["tac1"]))
    cgi1 = inc_hex(base["cgi1"], i, width=len(base["cgi1"]))
    pduSessionId1 = inc_int(base["pduSessionId1"], i)
    sip1 = inc_ip(base["sip1"], i % ip_num)
    dip1 = inc_ip(base["dip1"], i % ip_num)
    # sport1唯一且可控，避免五元组冲突
    sport1 = 10001 + ((i // ip_num) % 50000)
    global IP_REPLACEMENTS, JSON_FIELD_MAP
    IP_REPLACEMENTS = {
        "200.20.20.26": sip1,
        "200.20.20.25": dip1
    }
    JSON_FIELD_MAP = {
        "supi": f"imsi-{imsi1}",
        "pei": f"imeisv-{pei1}",
        "gpsi": f"msisdn-{gpsi1}",
        "dnn": dnn1,
        "ismfId": None,
        "icnTunnelInfo": {"ipv4Addr": upf1, "gtpTeid": teid1},
        "cnTunnelInfo": {"ipv4Addr": upf2, "gtpTeid": teid2},
        "ueIpv4Address": ueIP1,
        "tac": tac1,
        "nrCellId": cgi1,
        "uplink": "5000000000",
        "downlink": "5000000000",
        "ismfPduSessionUri": None
    }

def process_one_group(i, orig_packets_bytes, ip_num=1000):
    # 反序列化
    orig_packets = rdpcap(orig_packets_bytes)
    update_global_vars(i, ip_num)
    seq_diff = {}
    modified_packets = []
    for idx, pkt in enumerate(orig_packets, 1):
        pkt = pkt.copy()
        modified = False
        original_length = None
        new_length = None

        if idx in {9, 11, 13, 15} and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if idx == 15:
                direct_modified = apply_direct_binary_replacements(pkt, idx)
                raw = bytes(pkt[Raw].load)
                frames = extract_frames(raw)
                if not frames:
                    continue
                new_payload = b''
                headers_frame_modified = False
                data_frame_modified = False
                data_frame_length = 0
                for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                    if frame_type == 0x1:
                        new_header_data = process_special_headers(frame_data, idx)
                        if new_header_data != frame_data:
                            frame_header.length = len(new_header_data)
                            frames[frame_idx] = (frame_header, frame_type, new_header_data, start_offset, start_offset + 9 + len(new_header_data))
                            headers_frame_modified = True
                            modified = True
                    elif frame_type == 0x0:
                        new_data = process_http2_data_frame(frame_data)
                        if new_data is not None and new_data != frame_data:
                            data_frame_length = len(new_data)
                            frame_header.length = data_frame_length
                            frames[frame_idx] = (frame_header, frame_type, new_data, start_offset, start_offset + 9 + data_frame_length)
                            data_frame_modified = True
                            modified = True
                if data_frame_modified and headers_frame_modified and data_frame_length > 0:
                    for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                        if frame_type == 0x1:
                            new_cl_data = update_content_length(frame_data, data_frame_length)
                            if new_cl_data != frame_data:
                                frame_header.length = len(new_cl_data)
                                frames[frame_idx] = (frame_header, frame_type, new_cl_data, start_offset, start_offset + 9 + len(new_cl_data))
                for frame_header, _, frame_data, _, _ in frames:
                    new_payload += frame_header.build() + frame_data
                if modified:
                    original_length = len(raw)
                    new_length = len(new_payload)
                    pkt[Raw].load = new_payload
            else:
                raw = bytes(pkt[Raw].load)
                frames = extract_frames(raw)
                if not frames:
                    continue
                new_payload = b''
                data_length = None
                for frame_header, frame_type, frame_data, _, _ in frames:
                    if frame_type == 0x0:
                        new_data = process_http2_data_frame(frame_data)
                        if new_data is not None:
                            data_length = len(new_data)
                        else:
                            data_length = len(frame_data)
                        break
                for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                    if frame_type == 0x1:
                        new_header_data = process_special_headers(frame_data, idx, data_length)
                        new_header_data = update_content_length(new_header_data, data_length)
                        if new_header_data != frame_data:
                            modified = True
                            frame_header.length = len(new_header_data)
                            frames[frame_idx] = (frame_header, frame_type, new_header_data, start_offset, start_offset + 9 + len(new_header_data))
                for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                    if frame_type == 0x0:
                        new_data = process_http2_data_frame(frame_data)
                        if new_data is not None and new_data != frame_data:
                            modified = True
                            new_data_len = len(new_data)
                            frame_header.length = new_data_len
                            frames[frame_idx] = (frame_header, frame_type, new_data, start_offset, start_offset + 9 + new_data_len)
                for frame_header, _, frame_data, _, _ in frames:
                    new_payload += frame_header.build() + frame_data
                if modified:
                    original_length = len(raw)
                    new_length = len(new_payload)
                    pkt[Raw].load = new_payload
        process_packet(pkt, seq_diff, IP_REPLACEMENTS, original_length, new_length)
        modified_packets.append(pkt)
    return [bytes(pkt) for pkt in modified_packets]

def async_write_pcap(filename, packets):
    wrpcap(filename, packets)
    # 写完后主动释放内存
    del packets
    gc.collect()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='处理N16 PCAP文件中的HTTP/2帧')
    parser.add_argument('-i', '--input', dest='input_file', default="pcap/N16_create_16p.pcap",
                        help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', default="pcap/N16_1w.pcap",
                        help='输出PCAP文件路径')
    parser.add_argument('-n', '--num', dest='num', type=int, default=10000,
                        help='循环次数，生成报文组数')
    parser.add_argument('--ip-num', dest='ip_num', type=int, default=1000,
                        help='sip1/dip1循环数量，最大1000，支持自定义')
    args = parser.parse_args()
    PCAP_IN = args.input_file
    PCAP_OUT = args.output_file
    LOOP_NUM = args.num
    IP_NUM = args.ip_num

    if not os.path.exists(PCAP_IN):
        return

    orig_packets = rdpcap(PCAP_IN)
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        wrpcap(tf.name, orig_packets)
        orig_packets_bytes = tf.name

    # 主动释放原始PCAP数据
    del orig_packets
    gc.collect()

    BATCH_SIZE = 1000000  # 每批100万
    total_batches = LOOP_NUM // BATCH_SIZE
    remain = LOOP_NUM % BATCH_SIZE

    def get_outfile(base, idx):
        base_name, ext = os.path.splitext(base)
        return f"{base_name}_{idx+1:03d}{ext}"

    batch_idx = 0
    with ThreadPoolExecutor(max_workers=4) as file_writer:
        with concurrent.futures.ProcessPoolExecutor(max_workers=6) as executor:
            for i in range(total_batches):
                all_modified_packets = []
                func = partial(process_one_group, orig_packets_bytes=orig_packets_bytes, ip_num=IP_NUM)
                results = executor.map(func, range(i * BATCH_SIZE, (i + 1) * BATCH_SIZE))
                for group_bytes in tqdm(results, total=BATCH_SIZE, desc=f"Batch {i+1}/{total_batches+1}"):
                    for pkt_bytes in group_bytes:
                        all_modified_packets.append(Ether(pkt_bytes))
                out_file = get_outfile(PCAP_OUT, batch_idx)
                # 提交异步写任务
                file_writer.submit(async_write_pcap, out_file, all_modified_packets)
                # 主动清理
                del all_modified_packets
                gc.collect()
                batch_idx += 1

        if remain > 0:
            all_modified_packets = []
            with concurrent.futures.ProcessPoolExecutor(max_workers=6) as executor:
                func = partial(process_one_group, orig_packets_bytes=orig_packets_bytes, ip_num=IP_NUM)
                results = executor.map(func, range(total_batches * BATCH_SIZE, LOOP_NUM))
                for group_bytes in tqdm(results, total=remain, desc=f"Batch {batch_idx+1}/{total_batches+1}"):
                    for pkt_bytes in group_bytes:
                        all_modified_packets.append(Ether(pkt_bytes))
            out_file = get_outfile(PCAP_OUT, batch_idx)
            file_writer.submit(async_write_pcap, out_file, all_modified_packets)
            del all_modified_packets
            gc.collect()
    # 等待所有写任务完成
    file_writer.shutdown(wait=True)

    # 删除临时文件
    os.remove(orig_packets_bytes)
    gc.collect()

if __name__ == "__main__":
    main()