# N11接口批量处理脚本 - 基于n16_batch17_1000ip_perf.py架构改造
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether  
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
import tempfile

# 全局变量初始化
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
upfIP1 = "80.0.0.1"
upTEID1 = 0x70000001
gnbIP1 = "70.0.0.1"
dnTEID1 = 0x30000001
sport1 = 10001
sport2 = 10002
sport3 = 10003
sport4 = 10004
IP_REPLACEMENTS = {}
PORT_MAPPING = {}
TARGET_FIELDS = {}

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

def modify_json_data(payload, fields):
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
        
        def recursive_modify(obj):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in list(obj.items()):
                    lkey = key.lower()
                    # N11特殊处理smContextStatusUri字段
                    if lkey == "smcontextstatusuri" and isinstance(value, str):
                        new_value = re.sub(r'http://[^/]+', f'http://{sip1}', value)
                        if new_value != value:
                            obj[key] = new_value
                            modified = True
                    elif key in fields:
                        if value != fields[key]:
                            obj[key] = fields[key]
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

def process_http2_data_frame(frame_data, fields):
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
                        modified = modify_json_data(json_part, fields)
                        if modified:
                            parts[i + 1] = segments[0] + b"\r\n\r\n" + modified
        return b''.join(parts)
    else:
        try:
            modified = modify_json_data(frame_data, fields)
            return modified if modified else frame_data
        except Exception:
            return frame_data

def process_packet(pkt, seq_diff, ip_replacements, port_mapping, original_length=None, new_length=None):
    # IP地址替换
    if pkt.haslayer(IP):
        if pkt[IP].src in ip_replacements:
            pkt[IP].src = ip_replacements[pkt[IP].src]
        if pkt[IP].dst in ip_replacements:
            pkt[IP].dst = ip_replacements[pkt[IP].dst]
    
    # TCP端口替换
    if pkt.haslayer(TCP):
        if pkt[TCP].sport in port_mapping:
            pkt[TCP].sport = port_mapping[pkt[TCP].sport]
        if pkt[TCP].dport in port_mapping:
            pkt[TCP].dport = port_mapping[pkt[TCP].dport]
        
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
        
        # 清理校验和
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
        encoder = Encoder()
        
        # N11接口特定的关键报文处理
        if pkt_idx == 11:  # 第12个报文
            headers = [
                (b':method', b'POST'),
                (b':scheme', b'http'),
                (b':authority', auth1.encode('utf-8')),
                (b':path', b'/nsmf-pdusession/v1/sm-contexts'),
                (b'content-type', b'multipart/related; boundary=++Boundary'),
                (b'content-length', str(data_length).encode('utf-8') if data_length else b'0'),
                (b'accept', b'application/json'),
                (b'user-agent', b'AMF')
            ]
            return encoder.encode(headers)
            
        elif pkt_idx == 45:  # 第46个报文
            headers = [
                (b':status', b'201'),
                (b'content-type', b'multipart/related; boundary=++Boundary'),
                (b'location', f"http://{auth1}/nsmf-pdusession/v1/sm-contexts/{imsi1}-5".encode('utf-8')),
                (b'date', b'Wed, 22 May 2025 02:48:05 GMT'),
                (b'content-length', str(data_length).encode('utf-8') if data_length else b'0')
            ]
            return encoder.encode(headers)
            
        elif pkt_idx == 46:  # 第47个报文
            headers = [
                (b':method', b'POST'),
                (b':scheme', b'http'),
                (b':authority', auth2.encode('utf-8')),
                (b':path', f"/namf-comm/v1/ue-contexts/imsi-{imsi1}/n1-n2-messages".encode('utf-8')),
                (b'content-type', b'multipart/related; boundary=++Boundary'),
                (b'content-length', str(data_length).encode('utf-8') if data_length else b'0'),
                (b'user-agent', b'SMF')
            ]
            return encoder.encode(headers)
            
        elif pkt_idx == 48:  # 第49个报文
            headers = [
                (b':method', b'POST'),
                (b':scheme', b'http'),
                (b':authority', auth1.encode('utf-8')),
                (b':path', f"/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify".encode('utf-8')),
                (b'content-type', b'multipart/related; boundary=++Boundary'),
                (b'content-length', str(data_length).encode('utf-8') if data_length else b'0'),
                (b'accept', b'application/json'),
                (b'user-agent', b'SMF')
            ]
            return encoder.encode(headers)
        else:
            try:
                decoder = Decoder()
                headers = decoder.decode(frame_data)
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
            # 安全的字符串处理
            if isinstance(name, bytes):
                name_str = name.decode('utf-8', errors='ignore')
            else:
                name_str = str(name)
                
            if name_str.lower() == "content-length":
                if isinstance(value, bytes):
                    new_headers.append((name, str(body_length).encode('utf-8')))
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
                content_length_value = str(body_length).encode('utf-8')
            new_headers.append((content_length_key, content_length_value))
        
        return encoder.encode(new_headers)
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

def modify_binary_elements(frame_data, pkt_idx):
    """N11接口特定的二进制字段修改，包括GTP隧道信息"""
    modified_data = bytearray(frame_data)
    modifications_count = 0
    
    if pkt_idx == 46:  # 第47个报文 - PDU address + DNN + gTPTunnel
        # 1. 修改PDU address
        pdu_patterns = [b'\x29\x05\x01', b'\x29\x04', b'\x29']
        for pattern in pdu_patterns:
            pdu_pos = modified_data.find(pattern)
            if pdu_pos >= 0:
                ip_pos = pdu_pos + 3 if pattern == b'\x29\x05\x01' else pdu_pos + 2
                if ip_pos + 4 <= len(modified_data):
                    new_ip_parts = [int(x) for x in PduAddr1.split('.')]
                    modified_data[ip_pos:ip_pos+4] = new_ip_parts
                    modifications_count += 1
                    break
        
        # 2. 修改DNN
        dnn_pos = modified_data.find(b'\x25')
        if dnn_pos >= 0 and dnn_pos + 1 < len(modified_data):
            old_length = modified_data[dnn_pos + 1]
            dnn_data_start = dnn_pos + 2
            dnn_data_end = dnn_data_start + old_length
            
            if dnn_data_end <= len(modified_data):
                new_dnn_bytes = dnn1.encode('utf-8')
                new_length = 13
                if len(new_dnn_bytes) <= new_length - 1:
                    new_dnn_field = bytes([new_length, len(new_dnn_bytes)]) + new_dnn_bytes
                    new_data = (modified_data[:dnn_pos+1] + 
                               new_dnn_field + 
                               modified_data[dnn_data_end:])
                    modified_data = bytearray(new_data)
                    modifications_count += 1
        
        # 3. 修改gTPTunnel (UPF)
        original_ip = bytes([123, 1, 1, 20])
        original_teid = bytes([0x00, 0x1e, 0x84, 0x80])
        ip_pos = modified_data.find(original_ip)
        if ip_pos >= 0:
            teid_pos = ip_pos + 4
            if teid_pos + 4 <= len(modified_data):
                found_teid = bytes(modified_data[teid_pos:teid_pos+4])
                if found_teid == original_teid:
                    new_ip_parts = [int(x) for x in upfIP1.split('.')]
                    modified_data[ip_pos:ip_pos+4] = new_ip_parts
                    new_teid_bytes = upTEID1.to_bytes(4, 'big')
                    modified_data[teid_pos:teid_pos+4] = new_teid_bytes
                    modifications_count += 2
    
    elif pkt_idx == 48:  # 第49个报文 - gTPTunnel (gNB)
        original_ip = bytes([124, 1, 1, 3])
        original_teid = bytes([0x00, 0x00, 0x00, 0x01])
        ip_pos = modified_data.find(original_ip)
        if ip_pos >= 0:
            teid_pos = ip_pos + 4
            if teid_pos + 4 <= len(modified_data):
                found_teid = bytes(modified_data[teid_pos:teid_pos+4])
                if found_teid == original_teid:
                    new_ip_parts = [int(x) for x in gnbIP1.split('.')]
                    modified_data[ip_pos:ip_pos+4] = new_ip_parts
                    new_teid_bytes = dnTEID1.to_bytes(4, 'big')
                    modified_data[teid_pos:teid_pos+4] = new_teid_bytes
                    modifications_count += 2
    
    return bytes(modified_data)

# 递增函数
def inc_ip(ip, step=1):
    parts = list(map(int, ip.split('.')))
    val = (parts[0]<<24) + (parts[1]<<16) + (parts[2]<<8) + parts[3] + step
    return f"{(val>>24)&0xFF}.{(val>>16)&0xFF}.{(val>>8)&0xFF}.{val&0xFF}"

def inc_int(val, step=1):
    return str(int(val) + step)

def inc_hex(val, step=1):
    return val + step

def inc_port(port, step=1):
    new_port = port + step
    if new_port > 65535:
        new_port = 1024 + (new_port - 65536)
    return new_port

def calculate_optimized_ports(i, ip_num=4000):
    """
    优化的端口分配算法 - 确保40M循环无五元组冲突
    针对IP递增数量为4000、总循环量40,000,000次的场景
    
    策略：每个源端口分配2500个不重叠的目标端口范围
    - sport1 (10001): dport 1024-3523 (2500个端口)
    - sport2 (10002): dport 3524-6023 (2500个端口)  
    - sport3 (10003): dport 6024-8523 (2500个端口)
    - sport4 (10004): dport 8524-11023 (2500个端口)
    
    Args:
        i: 当前循环计数器
        ip_num: IP递增数量，默认4000
        
    Returns:
        tuple: (sport1, sport2, sport3, sport4, dport_base)
    """
    # 计算当前IP组内的循环位置
    ip_cycle = i % ip_num  # IP组内位置 (0-3999)
    port_cycle = i // ip_num  # 端口循环位置 (0-9999)
    
    # 基础源端口配置
    base_sports = [10001, 10002, 10003, 10004]
    
    # 每个源端口对应的目标端口范围
    port_ranges = [
        (1024, 3523),    # sport1: 2500个端口
        (3524, 6023),    # sport2: 2500个端口  
        (6024, 8523),    # sport3: 2500个端口
        (8524, 11023)    # sport4: 2500个端口
    ]
    
    # 计算当前使用的源端口组 (循环使用4个源端口)
    sport_group = port_cycle % 4
    
    # 计算目标端口偏移
    ports_per_group = 2500
    group_offset = port_cycle // 4  # 每完成4轮端口循环后的偏移
    dport_offset = group_offset % ports_per_group  # 在当前端口范围内的偏移
    
    # 计算实际使用的目标端口基值
    active_range = port_ranges[sport_group]
    dport_base = active_range[0] + dport_offset
    
    # 确保端口在有效范围内
    if dport_base > active_range[1]:
        dport_base = active_range[0] + (dport_base - active_range[0]) % (active_range[1] - active_range[0] + 1)
    
    # 返回所有源端口和计算出的目标端口基值
    return base_sports[0], base_sports[1], base_sports[2], base_sports[3], dport_base

def luhn_checksum(numstr: str) -> int:
    digits = [int(d) for d in numstr]
    oddsum = sum(digits[-1::-2])
    evensum = sum(sum(divmod(2 * d, 10)) for d in digits[-2::-2])
    return (oddsum + evensum) % 10

def imei14_to_imei15(imei14: str) -> str:
    check = luhn_checksum(imei14 + '0')
    check_digit = (10 - check) % 10
    return imei14 + str(check_digit)

def imei14_to_imeisv(imei14: str, sv: str = "00") -> str:
    return imei14 + sv

# 全局变量初始化
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
upfIP1 = "80.0.0.1"
upTEID1 = 0x70000001
gnbIP1 = "70.0.0.1"
dnTEID1 = 0x30000001
sport1 = 10001
sport2 = 10002
sport3 = 10003
sport4 = 10004
IP_REPLACEMENTS = {}
PORT_MAPPING = {}
TARGET_FIELDS = {}

def update_global_vars(i, ip_num=1000):
    global sip1, dip1, auth1, auth2, imsi1, imei14, gpsi1, PduAddr1, dnn1, tac1, cgi1
    global upfIP1, upTEID1, gnbIP1, dnTEID1, sport1, sport2, sport3, sport4
    global IP_REPLACEMENTS, PORT_MAPPING, TARGET_FIELDS
    
    # 基础值
    base = {
        "sip1": "40.0.0.1",
        "dip1": "50.0.0.1",
        "imsi1": "460012300000001",
        "imei14": "86111010000001",
        "gpsi1": "8613900000001",
        "PduAddr1": "100.0.0.1",
        "dnn1": "dnn600000001",
        "tac1": "100001",
        "cgi1": "010000001",
        "upfIP1": "80.0.0.1",
        "upTEID1": 0x70000001,
        "gnbIP1": "70.0.0.1",
        "dnTEID1": 0x30000001,
        "sport1": 10001,
        "sport2": 10002,
        "sport3": 10003,
        "sport4": 10004
    }
    
    # 递增所有变量
    sip1 = inc_ip(base["sip1"], i % ip_num)
    dip1 = inc_ip(base["dip1"], i % ip_num)
    auth1 = dip1
    auth2 = sip1
    
    imsi1 = inc_int(base["imsi1"], i)
    imei14 = f"{int(base['imei14']) + i:014d}"
    imei15 = imei14_to_imei15(imei14)
    pei1 = imei14_to_imeisv(imei14)
    
    gpsi1 = inc_int(base["gpsi1"], i)
    PduAddr1 = inc_ip(base["PduAddr1"], i)
    
    # DNN递增
    try:
        numeric_part = int(''.join(filter(str.isdigit, base["dnn1"])))
        prefix = ''.join(filter(str.isalpha, base["dnn1"]))
        dnn1 = f"{prefix}{numeric_part + i:09d}"
    except:
        dnn1 = base["dnn1"]
    
    tac1 = f"{int(base['tac1'], 16) + i:06X}"
    cgi1 = f"{int(base['cgi1'], 16) + i:09X}"
      # GTP隧道相关
    upfIP1 = inc_ip(base["upfIP1"], i)
    upTEID1 = inc_hex(base["upTEID1"], i)
    gnbIP1 = inc_ip(base["gnbIP1"], i)
    dnTEID1 = inc_hex(base["dnTEID1"], i)
      # 端口配置 - 使用优化算法确保无五元组冲突
    sport1, sport2, sport3, sport4, dport_base = calculate_optimized_ports(i, ip_num)
      # 全局映射配置
    IP_REPLACEMENTS = {
        "121.1.1.10": sip1,
        "123.1.1.10": dip1
    }
    
    PORT_MAPPING = {
        # 映射原始文件中实际存在的端口
        80: sport1,              # 原始HTTP端口 -> sport1
        10002: sport2,           # 原始sport2 -> 优化sport2
        10003: sport3,           # 原始sport3 -> 优化sport3
        10004: sport4,           # 原始sport4 -> 优化sport4
        10005: dport_base,       # 原始sport5 -> 优化目标端口
        # 目标端口的反向映射 (如果需要)
        # 注意：在原始文件中源端口和目标端口是相同的
    }
    
    TARGET_FIELDS = {
        "supi": f"imsi-{imsi1}",
        "pei": f"imeisv-{pei1}",
        "gpsi": f"msisdn-{gpsi1}",
        "dnn": dnn1,
        "tac": tac1,
        "nrCellId": cgi1,
        "smContextStatusUri": f"http://{sip1}/ntf-service/v1/nsmf-notify/0/pdusession-smcontextsts"
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
        
        # 关键N11报文处理
        if idx in {12, 46, 47, 49} and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            frames = extract_frames(raw)
            if not frames:
                continue
            
            new_payload = b''
            data_frame_length = None
            
            # 先处理DATA帧确定内容长度
            for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                if frame_type == 0x0:  # DATA frame
                    new_data = process_http2_data_frame(frame_data, TARGET_FIELDS)
                    if new_data is not None and new_data != frame_data:
                        # N11特殊处理：二进制字段修改
                        if idx in {47, 49}:
                            new_data = modify_binary_elements(new_data, idx-1)
                        data_frame_length = len(new_data)
                        frame_header.length = data_frame_length
                        frames[frame_idx] = (frame_header, frame_type, new_data, start_offset, start_offset + 9 + data_frame_length)
                        modified = True
                    else:
                        data_frame_length = len(frame_data)
                    break
            
            # 处理HEADERS帧
            for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                if frame_type == 0x1:  # HEADERS frame
                    new_header_data = process_special_headers(frame_data, idx-1, data_frame_length)
                    if new_header_data != frame_data:
                        modified = True
                        frame_header.length = len(new_header_data)
                        frames[frame_idx] = (frame_header, frame_type, new_header_data, start_offset, start_offset + 9 + len(new_header_data))
            
            # 重建payload
            for frame_header, _, frame_data, _, _ in frames:
                new_payload += frame_header.build() + frame_data
            
            if modified:
                original_length = len(raw)
                new_length = len(new_payload)
                pkt[Raw].load = new_payload
        
        process_packet(pkt, seq_diff, IP_REPLACEMENTS, PORT_MAPPING, original_length, new_length)
        modified_packets.append(pkt)
    
    return [bytes(pkt) for pkt in modified_packets]

def async_write_pcap(filename, packets):
    wrpcap(filename, packets)
    del packets
    gc.collect()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='处理N11 PCAP文件中的HTTP/2帧')
    parser.add_argument('-i', '--input', dest='input_file', default="pcap/N11_create_50p_portX.pcap",
                        help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', default="pcap/N11_create_2k.pcap",
                        help='输出PCAP文件路径')
    parser.add_argument('-n', '--num', dest='num', type=int, default=5000,
                        help='循环次数，生成报文组数')
    parser.add_argument('--ip-num', dest='ip_num', type=int, default=1000,
                        help='sip1/dip1循环数量，最大1000，支持自定义')
    
    args = parser.parse_args()
    PCAP_IN = args.input_file
    PCAP_OUT = args.output_file
    LOOP_NUM = args.num
    IP_NUM = args.ip_num
    
    if not os.path.exists(PCAP_IN):
        print(f"错误：输入文件 {PCAP_IN} 不存在")
        return
    
    orig_packets = rdpcap(PCAP_IN)
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        wrpcap(tf.name, orig_packets)
        orig_packets_bytes = tf.name
    
    # 主动释放原始PCAP数据
    del orig_packets
    gc.collect()
    
    BATCH_SIZE = 200000  # 每批20万
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
                file_writer.submit(async_write_pcap, out_file, all_modified_packets)
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
    
    print(f"✅ N11批量处理完成！")
    print(f"📊 总处理: {LOOP_NUM} 组数据包")
    print(f"💾 输出文件: {PCAP_OUT}")

if __name__ == "__main__":
    main()
