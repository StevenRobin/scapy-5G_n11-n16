# Windows优化的Scapy导入方式
import os
import sys

# 设置环境变量以避免Scapy在Windows上的导入问题
os.environ['SCAPY_USE_PCAPDNET'] = '0'
os.environ['SCAPY_USE_WINPCAPY'] = '0'

# 分别导入需要的Scapy模块，避免使用 scapy.all
from scapy.utils import rdpcap, wrpcap
from scapy.packet import Raw, Packet
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.fields import BitField, ByteField

print("Scapy模块导入成功")

from hpack import Encoder, Decoder
import json
import re
import copy
from tqdm import tqdm
from typing import Dict, Any, List, Optional
import os
import concurrent.futures
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from functools import partial
import tempfile
import gc
import time

# 全局配置参数 - 初始值
INITIAL_SIP1 = "40.0.0.1"
INITIAL_DIP1 = "50.0.0.1"
INITIAL_IMSI1 = "460012300000001"
INITIAL_IMEI14 = "86111010000001"
INITIAL_GPSI1 = "8613900000001"
INITIAL_PDUADDR1 = "100.0.0.1"
INITIAL_DNN1 = "dnn600000001"
INITIAL_TAC1 = "100001"
INITIAL_CGI1 = "010000001"
INITIAL_UPFIP1 = "80.0.0.1"
INITIAL_UPTEID1 = 0x70000001
INITIAL_GNBIP1 = "70.0.0.1"
INITIAL_DNTEID1 = 0x30000001
INITIAL_SPORT1 = 5001
INITIAL_SPORT2 = 5002  # sport1 + 1
INITIAL_SPORT3 = 5003  # sport1 + 2

# 全局变量 - 动态更新
sip1 = INITIAL_SIP1
dip1 = INITIAL_DIP1
auth1 = dip1
auth2 = sip1
imsi1 = INITIAL_IMSI1
imei14 = INITIAL_IMEI14
gpsi1 = INITIAL_GPSI1
PduAddr1 = INITIAL_PDUADDR1
dnn1 = INITIAL_DNN1
tac1 = INITIAL_TAC1
cgi1 = INITIAL_CGI1
upfIP1 = INITIAL_UPFIP1
upTEID1 = INITIAL_UPTEID1
gnbIP1 = INITIAL_GNBIP1
dnTEID1 = INITIAL_DNTEID1
sport1 = INITIAL_SPORT1
sport2 = INITIAL_SPORT2
sport3 = INITIAL_SPORT3

# IP和端口数量配置
IP_NUM = 2000      # 统一的IP循环数量
SPORT_NUM = 20000  # sport端口数量
TAC_NUM = 10000000 # TAC循环数量

def get_port_mapping():
    """动态获取当前端口映射，避免全局变量冲突"""
    return {
        20000: sport1,   # 20000 -> 10001
        51239: sport2,   # 51239 -> 10003
        55983: sport3    # 55983 -> 10004
    }

# 新增变量递增函数
def update_batch_variables(iteration):
    """更新一个批次的所有变量"""
    global sip1, dip1, auth1, auth2, imsi1, imei14, gpsi1, PduAddr1, dnn1, tac1, cgi1
    global upfIP1, upTEID1, gnbIP1, dnTEID1, sport1, sport2, sport3
    
    # IP地址循环递增 - 使用统一的IP_NUM
    ip_iteration = iteration % IP_NUM
    
    sip1 = inc_ip(INITIAL_SIP1, ip_iteration)
    dip1 = inc_ip(INITIAL_DIP1, ip_iteration)
    auth1 = dip1
    auth2 = sip1
    upfIP1 = inc_ip(INITIAL_UPFIP1, ip_iteration)
    gnbIP1 = inc_ip(INITIAL_GNBIP1, ip_iteration)
      # 数值字段+1递增
    imsi1 = inc_int(INITIAL_IMSI1, iteration)
    imei14 = inc_int(INITIAL_IMEI14, iteration)
    gpsi1 = inc_int(INITIAL_GPSI1, iteration)
    PduAddr1 = inc_ip(INITIAL_PDUADDR1, iteration)
    tac1 = inc_int(INITIAL_TAC1, iteration % TAC_NUM)  # 使用TAC_NUM进行循环
    cgi1 = inc_int(INITIAL_CGI1, iteration)
    upTEID1 = inc_hex(INITIAL_UPTEID1, iteration)
    dnTEID1 = inc_hex(INITIAL_DNTEID1, iteration)
    
    # DNN特殊处理
    try:
        numeric_part = int(''.join(filter(str.isdigit, INITIAL_DNN1)))
        prefix = ''.join(filter(str.isalpha, INITIAL_DNN1))
        dnn1 = f"{prefix}{numeric_part + iteration:09d}"
    except:
        dnn1 = INITIAL_DNN1
    
    # 端口+3递增，循环处理
    sport_iteration = (iteration * 3) % SPORT_NUM
    sport1 = inc_port(INITIAL_SPORT1, sport_iteration)
    sport2 = sport1 + 1  # sport1 + 1
    sport3 = sport1 + 2  # sport1 + 2

# 兼容性变量已移除，现在直接使用新变量名
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

def update_target_fields():
    """更新TARGET_FIELDS，使用当前变量值"""
    return {
        "supi": f"imsi-{imsi1}",
        "pei": f"imeisv-{imei14_to_imeisv(imei14)}",
        "gpsi": f"msisdn-{gpsi1}",    
        "dnn": dnn1,
        "tac": tac1,
        "nrCellId": cgi1,
        "smContextStatusUri": f"http://{sip1}/ntf-service/v1/nsmf-notify/0/pdusession-smcontextsts"    }

MODIFY_PATH_PREFIX = "/nsmf-pdusession/v1/sm-contexts/"
MODIFY_PATH_SUFFIX = "-5/modify"
LOCATION_HEADER_PREFIX = "http://123.1.1.10/nsmf-pdusession/v1/sm-contexts/"
LOCATION_HEADER_SUFFIX = "-5"

def inc_ip(ip: str, step: int = 1) -> str:
    """IP自增"""
    parts = list(map(int, ip.split('.')))
    val = (parts[0]<<24) + (parts[1]<<16) + (parts[2]<<8) + parts[3] + step
    return f"{(val>>24)&0xFF}.{(val>>16)&0xFF}.{(val>>8)&0xFF}.{val&0xFF}"

def inc_int(val: str, step: int = 1) -> str:
    return str(int(val) + step)

def inc_hex(val: int, step: int = 1) -> int:
    return val + step

def inc_port(port: int, step: int = 1) -> int:
    """端口自增，确保在有效范围内"""
    new_port = port + step
    # 确保端口在有效范围内 (1-65535)
    if new_port > 65535:
        new_port = 1024 + (new_port - 65536)  # 回绕到用户端口范围
    return new_port

def update_port_variables(step: int = 1):
    """更新全局端口变量"""
    global sport1, sport2, sport3
    sport1 = inc_port(sport1, step)
    sport2 = inc_port(sport2, step)
    sport3 = inc_port(sport3, step)
    # 移除重复的PORT_MAPPING更新，改用动态函数

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
                continue
            orig_type = type(value)
            # 其它字段正常处理
            if pkt_idx == 11 and name.lower() == ":authority":
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
            new_headers.append(("content-length", str(new_content_length)))
        encoder = Encoder()
        new_data = encoder.encode(new_headers)
        return new_data
    except Exception as e:
        return frame_data

def modify_json_data(payload, fields):
    try:
        if not payload.strip():
            return None
        data = json.loads(payload)
        modified = False
        def recursive_modify(obj, modifications):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in obj.items():
                    lkey = key.lower()
                    # 特殊处理smContextStatusUri字段，替换URL中的host部分
                    if lkey == "smcontextstatusuri" and isinstance(value, str):
                        # 使用正则表达式替换URL中的host部分为sip1
                        new_value = re.sub(r'http://[^/]+', f'http://{sip1}', value)
                        if new_value != value:
                            obj[key] = new_value
                            modified = True
                    else:
                        # 原有的字段匹配逻辑
                        for target in modifications:
                            if target.lower() == lkey:
                                obj[key] = modifications[target]
                                modified = True
                                break
                    if isinstance(value, (dict, list)):
                        recursive_modify(value, modifications)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        recursive_modify(item, modifications)
        recursive_modify(data, fields)
        return json.dumps(data, separators=(',', ':')).encode() if modified else None
    except Exception as e:
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
            
            # 验证帧结构
            if not validate_http2_frame_structure(raw, idx):
                print(f"[错误] 第{idx+1}号报文的HTTP/2帧结构异常")
            
            frames = extract_http2_frames(raw)
            headers_count = 0  # 跟踪HEADERS帧的数量
            for fidx, frame in enumerate(frames):
                frame_type = frame['type']
                frame_data = frame['data']
                if frame_type == 0x1:  # HEADERS
                    headers_count += 1
                    pkt_info.append({
                        'frame_idx': fidx,
                        'headers_index': headers_count,  # 这是第几个HEADERS帧
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

def batch_modify_targets(pkt_http2_info, target_fields):
    all_new_payloads = []
    for pkt_idx, pkt_info in enumerate(pkt_http2_info):
        if not pkt_info:
            all_new_payloads.append(None)
            continue
          # 添加调试信息
        if pkt_idx in (11, 46, 48):  # 只对关键报文调试
            debug_packet_frames(pkt_idx, pkt_info)
        
        new_frames = []
        # 先处理DATA帧，拿到新内容长度
        new_content_length = None
        data_frame_new_data = None
          # 确定是否有DATA帧并处理
        for entry in pkt_info:
            if entry['type'] == 'data':
                # 关键报文DATA帧精确处理
                if pkt_idx in (11, 46, 48):  # 关键报文12、47、49
                    data_frame_new_data = process_http2_data_frame_precise(pkt_idx, entry['data'], target_fields)
                else:
                    data_frame_new_data = process_http2_data_frame(entry['data'], target_fields)
                
                if data_frame_new_data:
                    new_content_length = len(data_frame_new_data)
                    entry['__new_data'] = data_frame_new_data
        
        # 重建各帧内容
        for entry in pkt_info:
            frame = entry['frame']
            if entry['type'] == 'headers':
                # 关键报文头部的严格重建
                if pkt_idx in (11, 45, 46, 48):  # 12、46、47、49号报文
                    new_frame_data = process_http2_headers_frame_precise(pkt_idx, new_content_length)
                    if new_frame_data is None:
                        # 兜底：用通用处理
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
    """更新IP地址和TCP端口"""
    if pkt.haslayer(IP):
        if pkt[IP].src == CLIENT_IP_OLD:
            pkt[IP].src = sip1
        elif pkt[IP].src == SERVER_IP_OLD:
            pkt[IP].src = dip1
        if pkt[IP].dst == CLIENT_IP_OLD:
            pkt[IP].dst = sip1
        elif pkt[IP].dst == SERVER_IP_OLD:
            pkt[IP].dst = dip1        # 使用动态端口映射
        if pkt.haslayer(TCP):
            port_mapping = get_port_mapping()  # 获取当前映射
            
            # 替换源端口
            if pkt[TCP].sport in port_mapping:
                pkt[TCP].sport = port_mapping[pkt[TCP].sport]
            
            # 替换目的端口
            if pkt[TCP].dport in port_mapping:
                pkt[TCP].dport = port_mapping[pkt[TCP].dport]

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

def process_http2_headers_frame_precise(pkt_idx, new_content_length=None):
    """
    针对关键报文（12、46、47、49）严格重建HTTP/2头部，顺序和内容准确。
    """
    encoder = Encoder()
    # 12、46、47、49为Wireshark序号，Python下从0计数，需-1
    if pkt_idx == 11:  # 第12个报文
        headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", auth1),
            (":path", "/nsmf-pdusession/v1/sm-contexts"),
            ("content-type", "multipart/related; boundary=++Boundary"),
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("accept", "application/json"),
            ("user-agent", "AMF"),
        ]
        return encoder.encode(headers)
    elif pkt_idx == 45:  # 第46个报文
        headers = [
            (":status", "201"),
            ("content-type", "multipart/related; boundary=++Boundary"),
            ("location", f"http://{auth1}/nsmf-pdusession/v1/sm-contexts/{imsi1}-5"),
            ("date", "Wed, 22 May 2025 02:48:05 GMT"),
            ("content-length", str(new_content_length) if new_content_length else "0"),
        ]
        return encoder.encode(headers)
    elif pkt_idx == 46:  # 第47个报文
        headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", auth2),
            (":path", f"/namf-comm/v1/ue-contexts/imsi-{imsi1}/n1-n2-messages"),
            ("content-type", "multipart/related; boundary=++Boundary"),
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("user-agent", "SMF"),
        ]
        return encoder.encode(headers)
    elif pkt_idx == 48:  # 第49个报文
        headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", auth1),
            (":path", f"/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify"),
            ("content-type", "multipart/related; boundary=++Boundary"),
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("accept", "application/json"),
            ("user-agent", "SMF"),
        ]
        return encoder.encode(headers)
    else:
        return None

# 函数已删除，因为报文中只有一个HEADERS帧

def process_http2_data_frame_precise(pkt_idx, frame_data, fields):
    """
    针对关键报文（12、47、49）DATA帧的精确处理，严格保持MIME结构
    """
    # 只处理含boundary的multipart
    if pkt_idx in (11, 46, 48) and b"--++Boundary" in frame_data:
        # 完全重建MIME结构，确保格式正确
        return rebuild_mime_structure(frame_data, fields, pkt_idx)
    else:
        # 如果不是multipart格式，使用标准处理
        return process_http2_data_frame(frame_data, fields)

def rebuild_mime_structure(frame_data, fields, pkt_idx):
    """重建完整的MIME结构，确保能正确解析"""
    
    # 特殊处理：如果是报文47，先在完整MIME数据中修改gTPTunnel
    if pkt_idx == 46:  # 第47号报文
        frame_data = modify_packet47_gtp_in_full_mime(frame_data)
    
    # 解析原始MIME结构
    parts = frame_data.split(b'--++Boundary')
    mime_parts = []
    
    for i, part in enumerate(parts[1:], 1):  # 跳过第一个空部分
        if not part or part == b'--\r\n':
            continue
            
        if b'\r\n\r\n' in part:
            headers_section, body_section = part.split(b'\r\n\r\n', 1)
            
            # 移除尾部的边界标记
            if b'\r\n--' in body_section:
                body_section = body_section.split(b'\r\n--', 1)[0]
            
            # 如果是JSON部分，处理字段修改
            if b'Content-Type:application/json' in headers_section:
                # 确保有Content-Id头
                if b'Content-Id:' not in headers_section:
                    content_id = "PduSessEstReq" if pkt_idx == 11 else f"Part{i}"
                    headers_section += f"\r\nContent-Id:{content_id}".encode()
                # 修改JSON内容
                modified_json = modify_json_data(body_section, fields)
                if modified_json:
                    body_section = modified_json
            else:
                # 非JSON部分，确保有Content-Id
                if b'Content-Id:' not in headers_section:
                    content_id = f"Part{i}"
                    headers_section += f"\r\nContent-Id:{content_id}".encode()
                # 处理二进制部分的MIME结构（针对第47、49报文的第2个部分）
                if (pkt_idx == 46 or pkt_idx == 48) and i == 2:  # 第2个部分（通常是二进制部分）
                    # 传递完整的frame_data作为full_mime_data参数
                    body_section = modify_binary_elements(body_section, pkt_idx, frame_data)
            
            # 重建这个MIME部分
            rebuilt_part = headers_section + b'\r\n\r\n' + body_section
            mime_parts.append(rebuilt_part)
        else:
            # 处理没有分隔符的部分（通常是只有头部没有体的部分）
            headers_section = part
            
            # 移除尾部的边界标记
            if b'\r\n--' in headers_section:
                headers_section = headers_section.split(b'\r\n--', 1)[0]
            
            # 确保有Content-Id头
            if b'Content-Id:' not in headers_section:
                content_id = f"Part{i}"
                headers_section += f"\r\nContent-Id:{content_id}".encode()
            
            # 重建这个MIME部分（添加分隔符和空体）
            rebuilt_part = headers_section + b'\r\n\r\n'
            mime_parts.append(rebuilt_part)
    
    # 重建完整的multipart内容
    result = b'--++Boundary'
    for part in mime_parts:
        result += part + b'\r\n--++Boundary'
    result += b'--\r\n'
    
    return result

def process_one_iteration(original_packets, iteration):
    """处理单次迭代的所有数据包"""
    # 更新变量
    update_batch_variables(iteration)
    target_fields = update_target_fields()
    
    # 处理数据包
    pkt_http2_info = batch_collect_targets(original_packets)
    all_new_payloads = batch_modify_targets(pkt_http2_info, target_fields)
    new_packets = update_packets(original_packets, all_new_payloads)
    
    return new_packets

def write_pcap_batch(packets, filename):
    """写入PCAP文件并回收内存"""
    try:
        # 修复数据包链路层类型问题
        fixed_packets = []
        for pkt in packets:
            if pkt.__class__.__name__ == 'Raw':
                # 如果是Raw包，包装为Ether帧以避免写入错误
                eth_pkt = Ether()/pkt
                fixed_packets.append(eth_pkt)
            else:
                fixed_packets.append(pkt)
        
        wrpcap(filename, fixed_packets)
        print(f"成功写入PCAP文件: {filename}, 包含 {len(fixed_packets)} 个数据包")
        
        # 清理内存
        del fixed_packets
        del packets
        import gc
        gc.collect()
        
    except Exception as e:
        print(f"写入PCAP文件失败: {filename}, 错误: {e}")

def main_batch_loop(
    pcap_in,
    pcap_out,
    total_iterations=1000,
    pcap_write_interval=200000,
    max_workers=6
):
    """主循环批量处理函数"""
    print("=== N11批量循环处理开始 ===")
    print(f"输入文件: {pcap_in}")
    print(f"输出文件前缀: {pcap_out}")
    print(f"总迭代次数: {total_iterations}")
    print(f"PCAP写入间隔: {pcap_write_interval}")
    print(f"线程数: {max_workers}")
    
    try:
        # 读取原始PCAP
        print("正在读取原始PCAP文件...")
        original_packets = rdpcap(pcap_in)
        print(f"成功读取 {len(original_packets)} 个数据包")
        
        all_packets = []
        pcap_file_count = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for i in tqdm(range(total_iterations), desc="处理进度"):
                # 提交处理任务
                future = executor.submit(process_one_iteration, copy.deepcopy(original_packets), i)
                batch_packets = future.result()
                all_packets.extend(batch_packets)
                
                # 检查是否需要写入PCAP
                if (i + 1) % pcap_write_interval == 0 or (i + 1) == total_iterations:
                    # 生成输出文件名
                    base_name, ext = os.path.splitext(pcap_out)
                    output_filename = f"{base_name}_{pcap_file_count + 1:03d}{ext}"
                    
                    # 写入PCAP文件
                    write_pcap_batch(all_packets, output_filename)
                    
                    # 重置累积包列表
                    all_packets = []
                    pcap_file_count += 1
                    
                    print(f"完成第 {pcap_file_count} 个PCAP文件，包含 {min(pcap_write_interval, total_iterations - i + pcap_write_interval - 1)} 次迭代")
        
        print(f"=== 批量处理完成，共生成 {pcap_file_count} 个PCAP文件 ===")
        
    except Exception as e:
        print(f"批量处理出错: {e}")
        import traceback
        traceback.print_exc()

def debug_packet_frames(pkt_idx, pkt_info):
    """调试函数：简化版本，避免在多进程环境中的输出冲突"""
    # 移除调试输出以避免多进程环境中的混乱输出
    pass

def validate_http2_frame_structure(raw_data, pkt_idx):
    """简化的HTTP/2帧结构验证"""
    frames = extract_http2_frames(raw_data)
    return len(frames) > 0

def modify_packet47_gtp_in_full_mime(frame_data):
    """
    专门处理第47个报文的gTPTunnel修改
    在完整的MIME数据中查找并修改gTPTunnel字段
    """
    global upfIP1, upTEID1
    
    # 目标IP和TEID
    original_ip = bytes([123, 1, 1, 20])  # 123.1.1.20
    original_teid = bytes([0x00, 0x1e, 0x84, 0x80])  # 0x1e8480
    
    modified_data = bytearray(frame_data)
    modifications_count = 0
    
    # 在完整数据中查找gTPTunnel
    ip_pos = modified_data.find(original_ip)
    if ip_pos >= 0:
        # 检查TEID
        teid_pos = ip_pos + 4
        if teid_pos + 4 <= len(modified_data):
            found_teid = bytes(modified_data[teid_pos:teid_pos+4])
            if found_teid == original_teid:
                # 修改IP地址
                new_ip_parts = [int(x) for x in upfIP1.split('.')]
                modified_data[ip_pos:ip_pos+4] = new_ip_parts
                upfIP1 = inc_ip(upfIP1)
                modifications_count += 1
                
                # 修改TEID
                new_teid_bytes = upTEID1.to_bytes(4, 'big')
                modified_data[teid_pos:teid_pos+4] = new_teid_bytes
                upTEID1 = inc_hex(upTEID1)
                modifications_count += 1
                
                return bytes(modified_data)
    
    return frame_data

def modify_binary_elements(frame_data, pkt_idx, full_mime_data=None):
    """
    修改二进制形式的MIME结构中的特定字段 - 基于实际gTPTunnel字段位置
    """
    global PduAddr1, dnn1, upfIP1, upTEID1, gnbIP1, dnTEID1
    
    modified_data = bytearray(frame_data)  # 使用bytearray便于修改
    modifications_count = 0
    
    # 报文47: 修改PDU address、DNN、gTPTunnel
    if pkt_idx == 46:
        # 1. 查找并修改PDU address (element ID=0x29)
        pdu_patterns = [
            b'\x29\x05\x01',      # 标准: ID=0x29, len=5, type=IPv4
            b'\x29\x04',          # 简化: ID=0x29, len=4
            b'\x29',              # 最基本: 只查找ID
        ]
        
        pdu_addr_found = False
        for i, pattern in enumerate(pdu_patterns):
            pdu_pos = modified_data.find(pattern)
            if pdu_pos >= 0:
                # 根据不同模式确定IP地址位置
                if i == 0:  # 完整模式
                    ip_pos = pdu_pos + 3
                elif i == 1:  # 简化模式
                    ip_pos = pdu_pos + 2
                else:  # 基本模式，需要跳过长度字节
                    if pdu_pos + 1 < len(modified_data):
                        length = modified_data[pdu_pos + 1]
                        if length >= 4:
                            ip_pos = pdu_pos + 2 + (length - 4)  # 假设IP在字段末尾
                        else:
                            continue
                    else:
                        continue
                
                # 修改IP地址
                if ip_pos + 4 <= len(modified_data):
                    new_ip_parts = [int(x) for x in PduAddr1.split('.')]
                    
                    # 验证新IP地址的合理性
                    if all(0 <= part <= 255 for part in new_ip_parts):
                        modified_data[ip_pos:ip_pos+4] = new_ip_parts
                        PduAddr1 = inc_ip(PduAddr1)
                        modifications_count += 1
                        pdu_addr_found = True
                        break
                else:
                    continue
        
        # 2. 查找并修改DNN (element ID=0x25)
        dnn_pos = modified_data.find(b'\x25')
        if dnn_pos >= 0 and dnn_pos + 1 < len(modified_data):
            old_length = modified_data[dnn_pos + 1]
            
            # 计算原DNN字段的结束位置
            dnn_data_start = dnn_pos + 2
            dnn_data_end = dnn_data_start + old_length
            
            if dnn_data_end <= len(modified_data):
                # 准备新的DNN数据
                new_dnn_bytes = dnn1.encode('utf-8')
                new_length = 13  # 固定长度13
                
                # 构建新的DNN字段: length + actual_length + data
                if len(new_dnn_bytes) <= new_length - 1:  # 预留1字节给实际长度
                    new_dnn_field = bytes([new_length, len(new_dnn_bytes)]) + new_dnn_bytes
                    
                    # 替换DNN字段 (保留element ID)
                    new_data = (modified_data[:dnn_pos+1] + 
                               new_dnn_field + 
                               modified_data[dnn_data_end:])
                    modified_data = bytearray(new_data)
                    
                    # 递增DNN
                    try:
                        numeric_part = int(''.join(filter(str.isdigit, dnn1)))
                        prefix = ''.join(filter(str.isalpha, dnn1))
                        dnn1 = f"{prefix}{numeric_part + 1:09d}"  # 保持9位数字
                    except:
                        pass
                    modifications_count += 1
        
        # 3. 第47号报文的gTPTunnel在rebuild_mime_structure中已经处理过了
        
    # 报文49: 修改gTPTunnel字段
    elif pkt_idx == 48:        # 查找并修改gTPTunnel字段（基于实际字段位置）
        # 第49号报文查找原始IP: 124.1.1.3 和 TEID: 0x1
        original_ip = bytes([124, 1, 1, 3])  # 124.1.1.3
        original_teid = bytes([0x00, 0x00, 0x00, 0x01])  # 0x1
        
        ip_pos = modified_data.find(original_ip)
        if ip_pos >= 0:
            # 检查后面4字节是否是原始TEID
            teid_pos = ip_pos + 4
            if teid_pos + 4 <= len(modified_data):
                found_teid = bytes(modified_data[teid_pos:teid_pos+4])
                if found_teid == original_teid:
                    # 修改IP地址
                    new_ip_parts = [int(x) for x in gnbIP1.split('.')]
                    modified_data[ip_pos:ip_pos+4] = new_ip_parts
                    gnbIP1 = inc_ip(gnbIP1)
                    modifications_count += 1
                    
                    # 修改TEID
                    new_teid_bytes = dnTEID1.to_bytes(4, 'big')
                    modified_data[teid_pos:teid_pos+4] = new_teid_bytes
                    dnTEID1 = inc_hex(dnTEID1)
                    modifications_count += 1
    
    return bytes(modified_data)

def process_one_group_n11(i, orig_packets_bytes, ip_num=2000, sport_num=20000):
    """
    N16风格的单组处理函数，适配N11逻辑
    在独立进程中处理单次迭代，避免pickle大对象
    """
    try:
        # 反序列化原始数据包
        original_packets = rdpcap(orig_packets_bytes)
        
        # 更新变量（基于迭代次数）
        update_batch_variables(i)
        target_fields = update_target_fields()
        
        # 处理数据包
        pkt_http2_info = batch_collect_targets(original_packets)
        all_new_payloads = batch_modify_targets(pkt_http2_info, target_fields)
        new_packets = update_packets(original_packets, all_new_payloads)
        
        # 序列化结果，避免复杂对象传递
        return [bytes(pkt) for pkt in new_packets]
        
    except Exception as e:
        print(f"处理组 {i} 时出错: {e}")
        return []

def async_write_pcap(filename, packets):
    """异步写入PCAP文件，带内存清理"""
    try:
        # 将字节数据重新转换为Ether包
        fixed_packets = []
        for pkt_bytes in packets:
            try:
                pkt = Ether(pkt_bytes)
                fixed_packets.append(pkt)
            except:
                # 如果转换失败，尝试作为Raw包处理
                pkt = Ether()/Raw(pkt_bytes)
                fixed_packets.append(pkt)
        
        wrpcap(filename, fixed_packets)
        print(f"✅ 成功写入: {filename} ({len(fixed_packets)} 包)")
        
        # 主动清理内存
        del fixed_packets
        del packets
        gc.collect()
        
    except Exception as e:
        print(f"❌ 写入失败: {filename}, 错误: {e}")

def async_write_pcap_fixed(filename, packets):
    fixed_packets = []
    packets_copy = None
    try:
        packets_copy = list(packets)  # 浅拷贝
        # 分批处理，错误隔离
        for pkt_bytes in packets_copy:
            if isinstance(pkt_bytes, bytes) and len(pkt_bytes) > 0:
                pkt = Ether(pkt_bytes)
                fixed_packets.append(pkt)
        wrpcap(filename, fixed_packets)
    finally:
        # 确保清理
        if fixed_packets:
            del fixed_packets
        if packets_copy:
            del packets_copy
        gc.collect()

def main_batch_n16_style(
    pcap_in,
    pcap_out,
    total_iterations=1000,
    pcap_write_interval=200000,
    process_workers=6,
    thread_workers=4
):
    """
    N16风格的混合架构处理函数
    ProcessPoolExecutor + ThreadPoolExecutor
    """
    print("=== N11 N16风格混合架构处理开始 ===")
    print(f"输入文件: {pcap_in}")
    print(f"输出文件前缀: {pcap_out}")
    print(f"总迭代次数: {total_iterations}")
    print(f"PCAP写入间隔: {pcap_write_interval}")
    print(f"进程池大小: {process_workers}")
    print(f"线程池大小: {thread_workers}")
    
    start_time = time.time()
    
    try:
        # 检查输入文件
        if not os.path.exists(pcap_in):
            print(f"❌ 输入文件不存在: {pcap_in}")
            return
        
        # 1. 临时文件序列化 (N16风格)
        print("🔄 序列化原始PCAP到临时文件...")
        orig_packets = rdpcap(pcap_in)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            wrpcap(tf.name, orig_packets)
            orig_packets_bytes = tf.name
        
        print(f"📦 成功读取 {len(orig_packets)} 个数据包")
        
        # 主动释放原始PCAP数据
        del orig_packets
        gc.collect()
        
        # 2. 计算批次分割
        BATCH_SIZE = pcap_write_interval  # 每批次大小
        total_batches = total_iterations // BATCH_SIZE
        remain = total_iterations % BATCH_SIZE
        
        print(f"📊 批次信息: {total_batches} 个完整批次 + {remain} 个剩余")
        
        def get_outfile(base, idx):
            """生成输出文件名"""
            base_name, ext = os.path.splitext(base)
            return f"{base_name}_{idx+1:03d}{ext}"
        
        # 3. 混合处理架构 (N16风格)
        batch_idx = 0
        with ThreadPoolExecutor(max_workers=thread_workers) as file_writer:
            # 处理完整批次
            for i in range(total_batches):
                print(f"🚀 处理批次 {i+1}/{total_batches + (1 if remain > 0 else 0)}")
                all_modified_packets = []
                
                # 使用进程池进行CPU密集型处理
                with ProcessPoolExecutor(max_workers=process_workers) as executor:
                    func = partial(process_one_group_n11, 
                                 orig_packets_bytes=orig_packets_bytes,
                                 ip_num=IP_NUM, sport_num=SPORT_NUM)
                    results = executor.map(func, range(i * BATCH_SIZE, (i + 1) * BATCH_SIZE))
                    
                    # 收集处理结果
                    for group_bytes in tqdm(results, total=BATCH_SIZE, 
                                          desc=f"Batch {i+1}", ncols=80):
                        all_modified_packets.extend(group_bytes)
                
                # 异步写入文件（不阻塞下一批处理）
                out_file = get_outfile(pcap_out, batch_idx)
                file_writer.submit(async_write_pcap, out_file, all_modified_packets)
                
                # 立即清理内存
                del all_modified_packets
                gc.collect()
                batch_idx += 1
            
            # 处理剩余组
            if remain > 0:
                print(f"🔄 处理剩余批次 {batch_idx+1}/{total_batches + 1}")
                all_modified_packets = []
                
                with ProcessPoolExecutor(max_workers=process_workers) as executor:
                    func = partial(process_one_group_n11,
                                 orig_packets_bytes=orig_packets_bytes,
                                 ip_num=IP_NUM, sport_num=SPORT_NUM)
                    results = executor.map(func, range(total_batches * BATCH_SIZE, total_iterations))
                    
                    for group_bytes in tqdm(results, total=remain, 
                                          desc=f"Batch {batch_idx+1}", ncols=80):
                        all_modified_packets.extend(group_bytes)
                
                out_file = get_outfile(pcap_out, batch_idx)
                file_writer.submit(async_write_pcap, out_file, all_modified_packets)
                
                del all_modified_packets
                gc.collect()
        
        # 等待所有写任务完成
        file_writer.shutdown(wait=True)
        
        # 清理临时文件
        os.remove(orig_packets_bytes)
        gc.collect()
        
        # 统计信息
        end_time = time.time()
        duration = end_time - start_time
        speed = total_iterations / duration if duration > 0 else 0
        
        print(f"\n✅ N11批量处理完成！")
        print(f"📊 总处理: {total_iterations} 组数据包")
        print(f"⏱️ 总耗时: {duration:.2f} 秒")
        print(f"🚄 处理速度: {speed:.0f} 组/秒")
        print(f"💾 输出文件: {pcap_out}")
        
    except Exception as e:
        print(f"❌ 处理出错: {e}")
        import traceback
        traceback.print_exc()

def main_batch_n16_style_optimized(
    pcap_in,
    pcap_out,
    total_iterations=1000,
    pcap_write_interval=200000,
    process_workers=6,
    thread_workers=4
):
    """
    优化版N16风格混合架构处理函数
    主要优化：避免进程池重建开销，提升第二批次及后续批次性能
    """
    print("=== N11 优化版混合架构处理开始 ===")
    print(f"输入文件: {pcap_in}")
    print(f"输出文件前缀: {pcap_out}")
    print(f"总迭代次数: {total_iterations}")
    print(f"PCAP写入间隔: {pcap_write_interval}")
    print(f"进程池大小: {process_workers}")
    print(f"线程池大小: {thread_workers}")
    
    start_time = time.time()
    
    try:
        # 检查输入文件
        if not os.path.exists(pcap_in):
            print(f"❌ 输入文件不存在: {pcap_in}")
            return
        
        # 1. 序列化原始PCAP到临时文件
        print("🔄 序列化原始PCAP到临时文件...")
        orig_packets = rdpcap(pcap_in)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            wrpcap(tf.name, orig_packets)
            orig_packets_bytes = tf.name
        
        print(f"📦 成功读取 {len(orig_packets)} 个数据包")
        
        # 主动释放原始PCAP数据
        del orig_packets
        gc.collect()
        
        # 2. 计算批次分割
        BATCH_SIZE = pcap_write_interval
        total_batches = total_iterations // BATCH_SIZE
        remain = total_iterations % BATCH_SIZE
        
        print(f"📊 批次信息: {total_batches} 个完整批次 + {remain} 个剩余")
        
        def get_outfile(base, idx):
            """生成输出文件名"""
            base_name, ext = os.path.splitext(base)
            return f"{base_name}_{idx+1:03d}{ext}"
        
        # 3. 优化的混合处理架构 - 共享进程池
        batch_idx = 0
        
        # ✅ 关键优化：创建一个长生命周期的进程池，避免重建开销
        with ProcessPoolExecutor(max_workers=process_workers) as shared_executor:
            with ThreadPoolExecutor(max_workers=thread_workers) as file_writer:
                
                # 预创建处理函数，避免重复创建
                func = partial(process_one_group_n11, 
                             orig_packets_bytes=orig_packets_bytes,
                             ip_num=IP_NUM, sport_num=SPORT_NUM)
                
                # 处理完整批次
                for i in range(total_batches):
                    print(f"🚀 处理批次 {i+1}/{total_batches + (1 if remain > 0 else 0)}")
                    
                    # ✅ 使用共享进程池，避免重建
                    batch_start_time = time.time()
                    results = shared_executor.map(func, range(i * BATCH_SIZE, (i + 1) * BATCH_SIZE))
                    
                    # 收集处理结果
                    all_modified_packets = []
                    for group_bytes in tqdm(results, total=BATCH_SIZE, 
                                          desc=f"Batch {i+1}", ncols=80):
                        all_modified_packets.extend(group_bytes)
                    
                    batch_process_time = time.time() - batch_start_time
                    
                    # 异步写入文件
                    out_file = get_outfile(pcap_out, batch_idx)
                    file_writer.submit(async_write_pcap, out_file, all_modified_packets)
                    
                    # ✅ 优化内存清理：减少gc.collect()频率
                    del all_modified_packets
                    if i % 3 == 0:  # 每3个批次才强制回收一次
                        gc.collect()
                    
                    batch_idx += 1
                    print(f"📊 批次 {i+1} 处理耗时: {batch_process_time:.2f}秒")
                
                # 处理剩余组
                if remain > 0:
                    print(f"🔄 处理剩余批次 {batch_idx+1}/{total_batches + 1}")
                    
                    batch_start_time = time.time()
                    results = shared_executor.map(func, range(total_batches * BATCH_SIZE, total_iterations))
                    
                    all_modified_packets = []
                    for group_bytes in tqdm(results, total=remain, 
                                          desc=f"Batch {batch_idx+1}", ncols=80):
                        all_modified_packets.extend(group_bytes)
                    
                    batch_process_time = time.time() - batch_start_time
                    
                    out_file = get_outfile(pcap_out, batch_idx)
                    file_writer.submit(async_write_pcap, out_file, all_modified_packets)
                    
                    del all_modified_packets
                    print(f"📊 剩余批次处理耗时: {batch_process_time:.2f}秒")
                
                # 等待所有写任务完成
                print("⏳ 等待所有文件写入完成...")
                file_writer.shutdown(wait=True)
        
        # 清理临时文件
        os.remove(orig_packets_bytes)
        gc.collect()
        
        # 统计信息
        end_time = time.time()
        duration = end_time - start_time
        speed = total_iterations / duration if duration > 0 else 0
        
        print(f"\n✅ N11优化版批量处理完成！")
        print(f"📊 总处理: {total_iterations} 组数据包")
        print(f"⏱️ 总耗时: {duration:.2f} 秒")
        print(f"🚄 处理速度: {speed:.0f} 组/秒")
        print(f"💾 输出文件: {pcap_out}")
        
    except Exception as e:
        print(f"❌ 处理出错: {e}")
        import traceback
        traceback.print_exc()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='N11批量循环PCAP处理工具')
    parser.add_argument('-i', '--input', dest='input_file', default="pcap/N11_create_50p.pcap",
                        help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', default="pcap/N11_create_6k.pcap",
                        help='输出PCAP文件前缀路径')
    parser.add_argument('-n', '--num', dest='num', type=int, default=6000,
                        help='循环次数，生成报文组数')
    parser.add_argument('--ip-num', dest='ip_num', type=int, default=2000,
                        help='IP循环数量，默认2000（sip1/dip1/upfIP1/gnbIP1统一使用）')
    parser.add_argument('--sport-num', dest='sport_num', type=int, default=20000,
                        help='sport端口循环数量，默认20000')
    parser.add_argument('--tac-num', dest='tac_num', type=int, default=1000000,
                        help='TAC循环数量，默认1000000')
    parser.add_argument('--pcap-interval', dest='pcap_interval', type=int, default=200000,                        help='每多少次循环写一个PCAP文件，默认200000')
    parser.add_argument('--threads', dest='threads', type=int, default=6,
                        help='线程数，默认6')
    parser.add_argument('--architecture', dest='architecture', 
                        choices=['original', 'n16', 'n16-optimized'], default='n16',
                        help='处理架构：original(原始ThreadPool) 或 n16(ProcessPool+ThreadPool混合) 或 n16-optimized(优化版，解决第二批次速度问题)，默认n16')
    parser.add_argument('--process-workers', dest='process_workers', type=int, default=6,
                        help='进程池大小，默认6（仅N16架构使用）')
    parser.add_argument('--thread-workers', dest='thread_workers', type=int, default=4,
                        help='线程池大小，默认4（仅N16架构使用）')
    
    args = parser.parse_args()
      # 更新全局配置
    global IP_NUM, SPORT_NUM, TAC_NUM
    IP_NUM = args.ip_num
    SPORT_NUM = args.sport_num
    TAC_NUM = args.tac_num
    
    # 检查输入文件
    if not os.path.exists(args.input_file):
        print(f"错误: 输入文件不存在: {args.input_file}")
        return
      # 根据选择的架构启动处理
    if args.architecture == 'n16-optimized':
        print("🚀 使用N16优化版混合架构 (共享进程池，解决第二批次速度问题)")
        main_batch_n16_style_optimized(
            pcap_in=args.input_file,
            pcap_out=args.output_file,
            total_iterations=args.num,
            pcap_write_interval=args.pcap_interval,
            process_workers=args.process_workers,
            thread_workers=args.thread_workers
        )
    elif args.architecture == 'n16':
        print("🚀 使用N16风格混合架构 (ProcessPoolExecutor + ThreadPoolExecutor)")
        main_batch_n16_style(
            pcap_in=args.input_file,
            pcap_out=args.output_file,
            total_iterations=args.num,
            pcap_write_interval=args.pcap_interval,
            process_workers=args.process_workers,
            thread_workers=args.thread_workers
        )
    else:
        print("🔄 使用原始ThreadPoolExecutor架构")
        main_batch_loop(
            pcap_in=args.input_file,
            pcap_out=args.output_file,
            total_iterations=args.num,
            pcap_write_interval=args.pcap_interval,
            max_workers=args.threads
        )

if __name__ == "__main__":
    print("=== N11批量循环处理程序启动 ===")
    print(f"🏗️ 支持三种架构:")
    print(f"   - original: 原始ThreadPoolExecutor架构")  
    print(f"   - n16: N16风格ProcessPoolExecutor+ThreadPoolExecutor混合架构")
    print(f"   - n16-optimized: 优化版混合架构 (推荐，解决第二批次速度问题)")
    print(f"📋 初始配置:")
    print(f"  sip1起始值: {INITIAL_SIP1}")
    print(f"  dip1起始值: {INITIAL_DIP1}")
    print(f"  imsi1起始值: {INITIAL_IMSI1}")
    print(f"  imei14起始值: {INITIAL_IMEI14}")
    print(f"  gpsi1起始值: {INITIAL_GPSI1}")
    print(f"  PduAddr1起始值: {INITIAL_PDUADDR1}")
    print(f"  dnn1起始值: {INITIAL_DNN1}")
    print(f"  tac1起始值: {INITIAL_TAC1}")
    print(f"  cgi1起始值: {INITIAL_CGI1}")
    print(f"  upfIP1起始值: {INITIAL_UPFIP1}")
    print(f"  upTEID1起始值: {hex(INITIAL_UPTEID1)}")
    print(f"  gnbIP1起始值: {INITIAL_GNBIP1}")
    print(f"  dnTEID1起始值: {hex(INITIAL_DNTEID1)}")
    print(f"  sport端口起始值: {INITIAL_SPORT1}(+3递增), {INITIAL_SPORT2}, {INITIAL_SPORT3}")
    print(f"  默认输入文件: pcap/N11_create_50p.pcap")
    print(f"  默认输出文件: pcap/N11_create_batch.pcap")
    print(f"  统一IP循环数量: {IP_NUM}")
    print(f"  TAC循环数量: {TAC_NUM}")
    
    try:
        main()
        print("✅ 程序正常结束")
    except Exception as e:
        print(f"❌ 程序异常结束: {e}")
        import traceback
        traceback.print_exc()