# Windows优化的Scapy导入方式
import os
import sys
import gc
import tempfile
import argparse
import threading
import queue
import time
from functools import partial
from typing import Dict, Any, List, Optional, Tuple

# 设置环境变量以避免Scapy在Windows上的导入问题
os.environ['SCAPY_USE_PCAPDNET'] = '0'
os.environ['SCAPY_USE_WINPCAPY'] = '0'

# 分别导入需要的Scapy模块，避免使用 scapy.all
from scapy.utils import rdpcap, wrpcap
from scapy.packet import Raw, Packet
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.fields import BitField, ByteField

from hpack import Encoder, Decoder
import json
import re
import copy
from tqdm import tqdm
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed

# 性能优化配置
BATCH_SIZE = 100  # 每批处理的包数量
MAX_WORKERS = min(4, os.cpu_count() or 4)  # 最大线程数
MEMORY_CLEANUP_INTERVAL = 500  # 内存清理间隔
PROGRESS_UPDATE_INTERVAL = 50  # 进度更新间隔

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

# 新变量配置 - 与新变量批量修改器保持一致
# 第47个报文的gTPTunnel字段
upfIP1 = "80.0.0.1"     # 原始值: 123.1.1.20
upTEID1 = 0x70000001    # 原始值: 0x001e8480

# 第49个报文的gTPTunnel字段  
gnbIP1 = "70.0.0.1"     # 原始值: 124.1.1.3
dnTEID1 = 0x30000001    # 原始值: 0x00000001

# 新增源端口变量 - 用于替换TCP会话中的源端口号
sport1 = 5001  # 替换原始端口20000，起始值5001
sport2 = 5002  # 替换原始端口51239，起始值5004
sport3 = 5003  # 替换原始端口55983，起始值5007

# 源端口映射表 - 原始端口到新端口的映射
def get_port_mapping(thread_vars=None):
    """动态获取当前端口映射，避免全局变量冲突"""
    if thread_vars:
        return {
            20000: thread_vars['sport1'],   # 20000 -> sport1
            51239: thread_vars['sport2'],   # 51239 -> sport2  
            55983: thread_vars['sport3']    # 55983 -> sport3
        }
    else:
        return {
            20000: sport1,   # 20000 -> sport1
            51239: sport2,   # 51239 -> sport2  
            55983: sport3    # 55983 -> sport3
        }

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

def inc_imei14(val, step=1):
    """14位IMEI递增，保持14位，不足补0"""
    v = int(val)
    v += step
    return f"{v:014d}"

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
    "nrCellId": cgi1,
    "smContextStatusUri": f"http://{sip1}/ntf-service/v1/nsmf-notify/0/pdusession-smcontextsts"
}

PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_create_2022.pcap"

MODIFY_PATH_PREFIX = "/nsmf-pdusession/v1/sm-contexts/"
MODIFY_PATH_SUFFIX = "-5/modify"
LOCATION_HEADER_PREFIX = "http://123.1.1.10/nsmf-pdusession/v1/sm-contexts/"
LOCATION_HEADER_SUFFIX = "-5"

def update_global_vars(i, ip_num=2000, port_num=20000):
    """更新全局变量，支持变量递增"""
    global sip1, dip1, auth1, auth2, imsi1, imei14, gpsi1, PduAddr1, dnn1, tac1, cgi1
    global upfIP1, upTEID1, gnbIP1, dnTEID1, sport1, sport2, sport3
    global TARGET_FIELDS
    
    # 基础值定义
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
        "sport1": 5001,
        "sport2": 5002,
        "sport3": 5003
    }
    
    # 递增所有变量
    sip1 = inc_ip(base["sip1"], i % ip_num)
    dip1 = inc_ip(base["dip1"], i % ip_num)
    auth1 = dip1
    auth2 = sip1
    imsi1 = inc_int(base["imsi1"], i)
    imei14 = inc_imei14(base["imei14"], i)
    gpsi1 = inc_int(base["gpsi1"], i)
    PduAddr1 = inc_ip(base["PduAddr1"], i)
    dnn1 = "dnn" + inc_int(base["dnn1"][3:], i)
    tac1 = inc_int(base["tac1"], i)
    cgi1 = inc_int(base["cgi1"], i)
    upfIP1 = inc_ip(base["upfIP1"], i % ip_num)
    upTEID1 = inc_hex(base["upTEID1"], i)
    gnbIP1 = inc_ip(base["gnbIP1"], i % ip_num) 
    dnTEID1 = inc_hex(base["dnTEID1"], i)
    
    # sport递增step=3，按照port_num循环
    sport1 = base["sport1"] + ((i % port_num) * 3)
    sport2 = base["sport2"] + ((i % port_num) * 3)
    sport3 = base["sport3"] + ((i % port_num) * 3)
    
    # 更新TARGET_FIELDS
    imei15 = imei14_to_imei15(imei14)
    pei1 = imei14_to_imeisv(imei14)
    
    TARGET_FIELDS = {
        "supi": f"imsi-{imsi1}",
        "pei": f"imeisv-{pei1}",
        "gpsi": f"msisdn-{gpsi1}",    
        "dnn": dnn1,
        "tac": tac1,
        "nrCellId": cgi1,
        "smContextStatusUri": f"http://{sip1}/ntf-service/v1/nsmf-notify/0/pdusession-smcontextsts"
    }

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
            
            if pkt_idx == 11 and name.lower() == ":authority":
                value = auth1
                modified = True
            elif pkt_idx == 45 and name.lower() == "location":
                if isinstance(value, (bytes, bytearray, memoryview)):
                    value = value.tobytes() if isinstance(value, memoryview) else bytes(value)
                    value = value.decode(errors='ignore')
                value = str(value).replace("123.1.1.10", auth1)
                modified = True
                if orig_type in (bytes, bytearray, memoryview):
                    value = value.encode()
            elif pkt_idx == 46 and name.lower() == ":authority":
                value = auth2
                modified = True
            elif pkt_idx == 48 and name.lower() == ":authority":
                value = auth1
                modified = True
            elif pkt_idx == 46 and name.lower() == ":path":
                if isinstance(value, (bytes, bytearray, memoryview)):
                    value = value.tobytes() if isinstance(value, memoryview) else bytes(value)
                    value = value.decode(errors='ignore')
                value = re.sub(r'imsi-\d+', f'imsi-{imsi1}', str(value))
                modified = True
                if orig_type in (bytes, bytearray, memoryview):
                    value = value.encode()
            elif pkt_idx == 48 and name.lower() == ":path":
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
    except Exception:
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
                    if lkey == "smcontextstatusuri" and isinstance(value, str):
                        new_value = re.sub(r'http://[^/]+', f'http://{sip1}', value)
                        if new_value != value:
                            obj[key] = new_value
                            modified = True
                    else:
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
    except Exception:
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
            
            # 验证帧结构（静默验证）
            validate_http2_frame_structure(raw, idx)
            
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
    return all_new_payloads

def update_ip(pkt, thread_vars=None):
    """更新IP地址和TCP端口"""
    # 使用线程变量或全局变量
    current_sip1 = thread_vars['sip1'] if thread_vars else sip1
    current_dip1 = thread_vars['dip1'] if thread_vars else dip1
    
    if pkt.haslayer(IP):
        if pkt[IP].src == CLIENT_IP_OLD:
            pkt[IP].src = current_sip1
        elif pkt[IP].src == SERVER_IP_OLD:
            pkt[IP].src = current_dip1
        if pkt[IP].dst == CLIENT_IP_OLD:
            pkt[IP].dst = current_sip1
        elif pkt[IP].dst == SERVER_IP_OLD:
            pkt[IP].dst = current_dip1
    
    # 使用动态端口映射
    if pkt.haslayer(TCP):
        port_mapping = get_port_mapping(thread_vars)
        
        # 替换源端口
        if pkt[TCP].sport in port_mapping:
            pkt[TCP].sport = port_mapping[pkt[TCP].sport]
        
        # 替换目的端口
        if pkt[TCP].dport in port_mapping:
            pkt[TCP].dport = port_mapping[pkt[TCP].dport]

def update_packets(original_packets, all_new_payloads, thread_vars=None):
    seq_diff = {}
    modified_packets = []
    for idx, pkt in enumerate(original_packets):
        pkt = copy.deepcopy(pkt)
        update_ip(pkt, thread_vars)
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
    """针对关键报文严格重建HTTP/2头部"""
    encoder = Encoder()
    
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
    """针对关键报文DATA帧的精确处理"""
    # 只处理含boundary的multipart
    if pkt_idx in (11, 46, 48) and b"--++Boundary" in frame_data:
        # 完全重建MIME结构，确保格式正确
        return rebuild_mime_structure(frame_data, fields, pkt_idx)
    else:
        # 如果不是multipart格式，使用标准处理
        return process_http2_data_frame(frame_data, fields)

def rebuild_mime_structure(frame_data, fields, pkt_idx):
    """重建完整的MIME结构，确保Wireshark能正确解析"""
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
                    # 添加Content-Id头
                    content_id = "PduSessEstReq" if pkt_idx == 11 else f"Part{i}"
                    headers_section += f"\r\nContent-Id:{content_id}".encode()                # 修改JSON内容
                modified_json = modify_json_data(body_section, fields)
                if modified_json:
                    body_section = modified_json
            else:
                # 非JSON部分，确保有Content-Id
                if b'Content-Id:' not in headers_section:
                    content_id = f"Part{i}"
                    headers_section += f"\r\nContent-Id:{content_id}".encode()                # 处理二进制部分的MIME结构（针对第47、49报文的第2个部分）
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

def process_one_batch(original_packets, batch_idx, total_batches, target_fields):
    print(f"[BATCH] 处理第{batch_idx+1}/{total_batches}批，共{len(original_packets)}包")
    pkt_http2_info = batch_collect_targets(original_packets)
    all_new_payloads = batch_modify_targets(pkt_http2_info, target_fields)
    new_packets = update_packets(original_packets, all_new_payloads)
    return new_packets

def process_batch_worker(batch_data: Tuple[int, Any, int, int]) -> List[Any]:
    """工作线程函数，处理单个批次"""
    # 声明全局变量访问
    global sip1, dip1, imsi1, imei14, gpsi1, PduAddr1, dnn1, tac1, cgi1
    global upfIP1, upTEID1, gnbIP1, dnTEID1, sport1, sport2, sport3
    
    batch_id, original_packets, ip_num, port_num = batch_data
    
    # 在工作线程中更新变量副本
    thread_local_vars = copy.deepcopy({
        'sip1': sip1, 'dip1': dip1, 'imsi1': imsi1, 'imei14': imei14,
        'gpsi1': gpsi1, 'PduAddr1': PduAddr1, 'dnn1': dnn1,
        'tac1': tac1, 'cgi1': cgi1, 'upfIP1': upfIP1, 'upTEID1': upTEID1,
        'gnbIP1': gnbIP1, 'dnTEID1': dnTEID1, 'sport1': sport1,
        'sport2': sport2, 'sport3': sport3
    })
    
    # 为这个批次更新变量
    update_global_vars_for_batch(batch_id, ip_num, port_num, thread_local_vars)
    
    # 保存原始全局变量
    orig_globals = {
        'sip1': sip1, 'dip1': dip1, 'imsi1': imsi1, 'imei14': imei14,
        'gpsi1': gpsi1, 'PduAddr1': PduAddr1, 'dnn1': dnn1,
        'tac1': tac1, 'cgi1': cgi1, 'upfIP1': upfIP1, 'upTEID1': upTEID1,
        'gnbIP1': gnbIP1, 'dnTEID1': dnTEID1, 'sport1': sport1,
        'sport2': sport2, 'sport3': sport3
    }
    
    try:
        # 临时设置全局变量为线程局部值
        sip1 = thread_local_vars['sip1']
        dip1 = thread_local_vars['dip1']
        imsi1 = thread_local_vars['imsi1']
        imei14 = thread_local_vars['imei14']
        gpsi1 = thread_local_vars['gpsi1']
        PduAddr1 = thread_local_vars['PduAddr1']
        dnn1 = thread_local_vars['dnn1']
        tac1 = thread_local_vars['tac1']
        cgi1 = thread_local_vars['cgi1']
        upfIP1 = thread_local_vars['upfIP1']
        upTEID1 = thread_local_vars['upTEID1']
        gnbIP1 = thread_local_vars['gnbIP1']
        dnTEID1 = thread_local_vars['dnTEID1']
        sport1 = thread_local_vars['sport1']
        sport2 = thread_local_vars['sport2']
        sport3 = thread_local_vars['sport3']
        
        # 复制包并处理
        current_packets = [copy.deepcopy(pkt) for pkt in original_packets]
        
        # 处理当前批次
        pkt_http2_info = batch_collect_targets(current_packets)
        target_fields = build_target_fields(thread_local_vars)
        all_new_payloads = batch_modify_targets(pkt_http2_info, target_fields)
        new_packets = update_packets(current_packets, all_new_payloads, thread_local_vars)
        
        return new_packets
        
    finally:
        # 恢复原始全局变量
        sip1 = orig_globals['sip1']
        dip1 = orig_globals['dip1']
        imsi1 = orig_globals['imsi1']
        imei14 = orig_globals['imei14']
        gpsi1 = orig_globals['gpsi1']
        PduAddr1 = orig_globals['PduAddr1']
        dnn1 = orig_globals['dnn1']
        tac1 = orig_globals['tac1']
        cgi1 = orig_globals['cgi1']
        upfIP1 = orig_globals['upfIP1']
        upTEID1 = orig_globals['upTEID1']
        gnbIP1 = orig_globals['gnbIP1']
        dnTEID1 = orig_globals['dnTEID1']
        sport1 = orig_globals['sport1']
        sport2 = orig_globals['sport2']
        sport3 = orig_globals['sport3']

def update_global_vars_for_batch(i: int, ip_num: int, port_num: int, vars_dict: Dict[str, Any]):
    """为批次更新变量字典"""
    base = {
        "sip1": "40.0.0.1", "dip1": "50.0.0.1", "imsi1": "460012300000001",
        "imei14": "86111010000001", "gpsi1": "8613900000001", "PduAddr1": "100.0.0.1",
        "dnn1": "dnn600000001", "tac1": "100001", "cgi1": "010000001",
        "upfIP1": "80.0.0.1", "upTEID1": 0x70000001, "gnbIP1": "70.0.0.1", 
        "dnTEID1": 0x30000001, "sport1": 5001, "sport2": 5002, "sport3": 5003
    }
    
    vars_dict['sip1'] = inc_ip(base["sip1"], i % ip_num)
    vars_dict['dip1'] = inc_ip(base["dip1"], i % ip_num)
    vars_dict['imsi1'] = inc_int(base["imsi1"], i)
    vars_dict['imei14'] = inc_imei14(base["imei14"], i)
    vars_dict['gpsi1'] = inc_int(base["gpsi1"], i)
    vars_dict['PduAddr1'] = inc_ip(base["PduAddr1"], i)
    vars_dict['dnn1'] = "dnn" + inc_int(base["dnn1"][3:], i)
    vars_dict['tac1'] = inc_int(base["tac1"], i)
    vars_dict['cgi1'] = inc_int(base["cgi1"], i)
    vars_dict['upfIP1'] = inc_ip(base["upfIP1"], i % ip_num)
    vars_dict['upTEID1'] = inc_hex(base["upTEID1"], i)
    vars_dict['gnbIP1'] = inc_ip(base["gnbIP1"], i % ip_num) 
    vars_dict['dnTEID1'] = inc_hex(base["dnTEID1"], i)
    vars_dict['sport1'] = base["sport1"] + ((i % port_num) * 3)
    vars_dict['sport2'] = base["sport2"] + ((i % port_num) * 3)
    vars_dict['sport3'] = base["sport3"] + ((i % port_num) * 3)

def build_target_fields(vars_dict: Dict[str, Any]) -> Dict[str, str]:
    """构建目标字段字典"""
    imei15 = imei14_to_imei15(vars_dict['imei14'])
    pei1 = imei14_to_imeisv(vars_dict['imei14'])
    
    return {
        "supi": f"imsi-{vars_dict['imsi1']}",
        "pei": f"imeisv-{pei1}",
        "gpsi": f"msisdn-{vars_dict['gpsi1']}",    
        "dnn": vars_dict['dnn1'],
        "tac": vars_dict['tac1'],
        "nrCellId": vars_dict['cgi1'],
        "smContextStatusUri": f"http://{vars_dict['sip1']}/ntf-service/v1/nsmf-notify/0/pdusession-smcontextsts"
    }

def main_batch(
    pcap_in=PCAP_IN,
    pcap_out=PCAP_OUT,
    loop_num=1,
    ip_num=2000,
    port_num=20000
):
    start_time = time.time()
    print("=== 高性能批量处理开始 ===")
    print(f"输入文件: {pcap_in}")
    print(f"输出文件: {pcap_out}")
    print(f"循环次数: {loop_num}")
    print(f"IP循环数量: {ip_num}")
    print(f"端口循环数量: {port_num}")
    print(f"工作线程数: {MAX_WORKERS}")
    
    try:
        # 读取原始数据包
        original_packets = rdpcap(pcap_in)
        print(f"成功读取PCAP文件，包含 {len(original_packets)} 个数据包")
        
        # 准备批次数据
        batch_tasks = [(i, original_packets, ip_num, port_num) for i in range(loop_num)]
        
        all_packets = []
        processed_count = 0
        
        # 使用线程池处理批次
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # 创建进度条
            with tqdm(total=loop_num, desc="处理进度", unit="批次") as pbar:
                # 提交所有任务
                future_to_batch = {
                    executor.submit(process_batch_worker, batch_data): batch_id 
                    for batch_id, batch_data in enumerate(batch_tasks)
                }
                
                # 收集结果
                for future in as_completed(future_to_batch):
                    try:
                        batch_result = future.result()
                        all_packets.extend(batch_result)
                        processed_count += 1
                        pbar.update(1)
                        
                        # 定期内存清理
                        if processed_count % MEMORY_CLEANUP_INTERVAL == 0:
                            gc.collect()
                            
                    except Exception as e:
                        batch_id = future_to_batch[future]
                        print(f"批次 {batch_id} 处理失败: {e}")
        
        # 优化数据包格式
        print("优化数据包格式...")
        fixed_packets = []
        for pkt in tqdm(all_packets, desc="格式优化"):
            if pkt.__class__.__name__ == 'Raw':
                fixed_packets.append(Ether()/pkt)
            else:
                fixed_packets.append(pkt)
        
        # 保存结果
        print(f"保存结果到 {pcap_out}...")
        wrpcap(pcap_out, fixed_packets)
        
        # 性能统计
        end_time = time.time()
        total_time = end_time - start_time
        packets_per_second = len(fixed_packets) / total_time if total_time > 0 else 0
        
        print(f"=== 处理完成 ===")
        print(f"总处理时间: {total_time:.2f} 秒")
        print(f"输出包数量: {len(fixed_packets)}")
        print(f"处理速度: {packets_per_second:.0f} 包/秒")
        print(f"内存清理次数: {processed_count // MEMORY_CLEANUP_INTERVAL}")
        
    except Exception as e:
        print(f"程序执行出错: {e}")
        import traceback
        traceback.print_exc()

def debug_packet_frames(pkt_idx, pkt_info):
    """调试函数：已优化移除调试输出"""
    pass

def validate_http2_frame_structure(raw_data, pkt_idx):
    """验证HTTP/2帧结构的有效性"""
    frames = extract_http2_frames(raw_data)
    headers_count = sum(1 for f in frames if f['type'] == 0x1)
    data_count = sum(1 for f in frames if f['type'] == 0x0)
    return headers_count > 0  # 至少需要有头部帧

def modify_packet47_gtp_in_full_mime(frame_data):
    """专门处理第47个报文的gTPTunnel修改"""
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
    
    根据调试结果，实际的gTPTunnel字段位置：
    - 第47个报文: IP=123.1.1.20 位置19, TEID=0x1e8480, 目标: upfIP1=80.0.0.1, upTEID1=0x70000001
    - 第49个报文: IP=124.1.1.3 位置3, TEID=0x1, 目标: gnbIP1=70.0.0.1, dnTEID1=0x30000001
    
    参数:
    - frame_data: 小的数据段（MIME body section）
    - pkt_idx: 报文索引
    - full_mime_data: 完整的MIME数据（用于搜索gTPTunnel）    """
    global PduAddr1, dnn1, upfIP1, upTEID1, gnbIP1, dnTEID1
    
    modified_data = bytearray(frame_data)  # 使用bytearray便于修改
    modifications_count = 0
      # 报文47: 修改PDU address、DNN、gTPTunnel
    if pkt_idx == 46:
        # 1. 查找并修改PDU address (element ID=0x29)
        # 改进的PDU address查找策略
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
                    old_ip_bytes = modified_data[ip_pos:ip_pos+4]
                    old_ip = '.'.join(str(b) for b in old_ip_bytes)
                    new_ip_parts = [int(x) for x in PduAddr1.split('.')]
                    
                    # 验证新IP地址的合理性
                    if all(0 <= part <= 255 for part in new_ip_parts):
                        modified_data[ip_pos:ip_pos+4] = new_ip_parts
                        PduAddr1 = inc_ip(PduAddr1)
                        modifications_count += 1
                        pdu_addr_found = True
                        break
          # 2. 查找并修改DNN (element ID=0x25)
        dnn_pos = modified_data.find(b'\x25')
        if dnn_pos >= 0 and dnn_pos + 1 < len(modified_data):
            old_length = modified_data[dnn_pos + 1]
            
            # 计算原DNN字段的结束位置
            dnn_data_start = dnn_pos + 2
            dnn_data_end = dnn_data_start + old_length
            
            if dnn_data_end <= len(modified_data):
                # 读取原DNN数据
                old_dnn_data = bytes(modified_data[dnn_data_start:dnn_data_end])
                
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
                        pass  # DNN递增失败，保持原值
                    modifications_count += 1        # 3. 第47号报文的gTPTunnel在rebuild_mime_structure中已经处理过了
        pass  # 跳过此步骤
        
    # 报文49: 修改gTPTunnel字段
    elif pkt_idx == 48:
        # 查找并修改gTPTunnel字段（基于实际字段位置）
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


def find_gtp_tunnel_by_protocol_ie(data, pkt_num):
    """
    基于ProtocolIE-Field ID查找gTPTunnel的TransportLayerAddress和gTP-TEID
    
    参数:
    - data: 二进制数据
    - pkt_num: 报文号码(47或49)
    
    返回:
    - (ip_pos, teid_pos): IP地址和TEID的位置，如果未找到返回(-1, -1)
    """
    print(f"\n[GTP-IE] 基于ProtocolIE-Field查找报文{pkt_num}的gTPTunnel字段...")
    
    if pkt_num == 47:
        # 第47个报文：查找id-UL-NGU-UP-TNLInformation (139)
        # ASN.1编码：139 = 0x8B，通常编码为 0x00 0x8B 或在上下文中可能是其他形式
        print("[GTP-IE] 查找id-UL-NGU-UP-TNLInformation (139)...")
        
        # 不同的编码可能性
        ie_patterns = [
            b'\x00\x8b',          # 直接的139编码 
            b'\x8b',              # 简化编码
            b'\x00\x00\x8b',      # 扩展编码
            b'\x01\x39',          # 另一种可能的编码(1*256+57=313, 但139的BCD可能)
            b'\x89\x03',          # 可能的变体编码
        ]
        
        # 同时查找UL-NGU相关的字符串模式
        string_patterns = [
            b'UL-NGU',
            b'TNLInformation', 
            b'TransportLayer',
        ]
        
    elif pkt_num == 49:
        # 第49个报文：查找dLQosFlowPerTNLInformation
        print("[GTP-IE] 查找dLQosFlowPerTNLInformation...")
        
        ie_patterns = [
            b'dLQosFlow',
            b'QosFlow', 
            b'TNLInfo',
            b'PerTNL',
        ]
        
        # 数字模式（如果有特定的IE ID）
        string_patterns = [
            b'\x00\x7a',          # 可能的ID值
            b'\x7a',              # 简化
            b'DL',                # 下行相关
        ]
    
    else:
        print(f"[GTP-IE] 不支持的报文号: {pkt_num}")
        return (-1, -1)
    
    # 策略1: 查找ProtocolIE-Field模式
    ie_found_pos = -1
    found_pattern = None
    
    for pattern in ie_patterns:
        pos = data.find(pattern)
        if pos >= 0:
            print(f"[GTP-IE] 找到IE模式 '{pattern}' 在位置 {pos}")
            ie_found_pos = pos
            found_pattern = pattern
            break
    
    # 策略2: 如果策略1失败，查找字符串模式
    if ie_found_pos == -1:
        for pattern in string_patterns:
            pos = data.find(pattern)
            if pos >= 0:
                print(f"[GTP-IE] 找到字符串模式 '{pattern}' 在位置 {pos}")
                ie_found_pos = pos  
                found_pattern = pattern
                break
    
    if ie_found_pos == -1:
        print(f"[GTP-IE] 未找到报文{pkt_num}的ProtocolIE-Field标识")
        return (-1, -1)
    
    # 在找到的IE位置附近搜索TransportLayerAddress和gTP-TEID
    print(f"[GTP-IE] 在IE位置 {ie_found_pos} 附近搜索TransportLayerAddress...")
    
    # 搜索范围：IE位置前后50字节
    search_start = max(0, ie_found_pos - 50)
    search_end = min(len(data) - 8, ie_found_pos + 100)
    
    # 查找TransportLayerAddress（通常是IP地址，4字节）
    target_first_byte = 80 if pkt_num == 47 else 70
    ip_pos = -1
    teid_pos = -1
    
    print(f"[GTP-IE] 在范围 {search_start}-{search_end} 内查找 {target_first_byte}.x.x.x 格式的IP地址...")
    
    for pos in range(search_start, search_end):
        if pos + 8 <= len(data):  # 需要至少8字节（IP+TEID）
            # 检查是否是目标IP地址
            if data[pos] == target_first_byte:
                # 验证后续3字节是否构成合理的IP地址
                ip_candidate = data[pos:pos+4]
                if all(0 <= byte <= 255 for byte in ip_candidate):
                    ip_str = '.'.join(str(b) for b in ip_candidate)
                    print(f"[GTP-IE] 找到候选IP地址: {ip_str} 在位置 {pos}")
                    
                    # 检查前后的上下文，确认这是TransportLayerAddress
                    context_before = data[max(0, pos-8):pos].hex()
                    context_after = data[pos+4:pos+12].hex() 
                    print(f"[GTP-IE] IP前8字节: {context_before}")
                    print(f"[GTP-IE] IP后8字节: {context_after}")
                    
                    # 简单的启发式验证：
                    # 1. 前面可能有长度标识
                    # 2. 后面4字节可能是TEID
                    validation_score = 0
                    
                    # 检查前面是否有长度标识（0x04表示4字节IP）
                    if pos > 0 and data[pos-1] == 0x04:
                        validation_score += 2
                        print(f"[GTP-IE] 发现长度标识 0x04")
                    
                    # 检查前面是否有TransportLayerAddress的标识
                    if pos > 1 and data[pos-2] in [0x00, 0x01, 0x40, 0x80]:
                        validation_score += 1
                        print(f"[GTP-IE] 发现可能的地址类型标识: {hex(data[pos-2])}")
                      # 检查后面4字节是否是合理的TEID值
                    teid_candidate = data[pos+4:pos+8]
                    teid_value = int.from_bytes(teid_candidate, 'big')
                    if 0x10000000 <= teid_value <= 0xFFFFFFFF:  # 合理的TEID范围
                        validation_score += 2
                        print(f"[GTP-IE] 发现合理的TEID: {hex(teid_value)}")
                    
                    print(f"[GTP-IE] 验证分数: {validation_score}/5")
                    
                    # 如果验证分数足够高，认为找到了正确的位置
                    if validation_score >= 2:
                        ip_pos = pos
                        teid_pos = pos + 4
                        print(f"[GTP-IE] ✅ 确认找到TransportLayerAddress和gTP-TEID")
                        print(f"[GTP-IE]    IP位置: {ip_pos}, TEID位置: {teid_pos}")
                        break
    
    if ip_pos == -1:
        print(f"[GTP-IE] ❌ 未找到有效的TransportLayerAddress")
        return (-1, -1)
    
    return (ip_pos, teid_pos)


def modify_gtp_tunnel_fields(data, pkt_num, ip_value, teid_value, ip_var_name):
    """
    修改gTPTunnel字段的IP和TEID
    返回修改的字段数量
    """
    global upfIP1, upTEID1, gnbIP1, dnTEID1
    
    modifications = 0
    
    print(f"[GTP] 开始查找报文{pkt_num}的gTPTunnel字段...")
    print(f"[GTP] 数据长度: {len(data)}")
    print(f"[GTP] 完整数据十六进制: {data.hex()}")
    
    # 策略1: 直接搜索可能的IP地址
    target_first_byte = 80 if pkt_num == 47 else 70
    print(f"[GTP] 查找以{target_first_byte}开头的IP地址...")
    
    # 在整个数据中搜索目标IP地址模式
    for i in range(len(data) - 7):  # 至少需要8字节（IP+TEID）
        if data[i] == target_first_byte:
            # 检查是否是合理的IP地址
            ip_candidate = data[i:i+4]
            ip_str = '.'.join(str(b) for b in ip_candidate)
            
            # 验证IP地址的合理性
            if all(0 <= byte <= 255 for byte in ip_candidate):
                print(f"[GTP] 在位置{i}找到候选IP: {ip_str}")
                
                # 检查是否在合理的上下文中（前后几个字节的模式）
                context_start = max(0, i - 8)
                context_end = min(len(data), i + 12)
                context = data[context_start:context_end]
                print(f"[GTP] 上下文({context_start}-{context_end}): {context.hex()}")
                  # 修改IP地址
                new_ip_parts = [int(x) for x in ip_value.split('.')]
                data[i:i+4] = new_ip_parts
                print(f"[SUCCESS] gTPTunnel IP修改: {ip_str} -> {ip_value}")
                # 修改对应的全局变量
                if pkt_num == 47:
                    upfIP1 = inc_ip(upfIP1)
                else:
                    gnbIP1 = inc_ip(gnbIP1)
                
                modifications += 1
                
                # 检查并修改TEID（紧接着IP地址的4字节）
                teid_pos = i + 4
                if teid_pos + 4 <= len(data):
                    old_teid_bytes = data[teid_pos:teid_pos+4]
                    old_teid = int.from_bytes(old_teid_bytes, 'big')
                    new_teid_bytes = teid_value.to_bytes(4, 'big')
                    data[teid_pos:teid_pos+4] = new_teid_bytes
                    print(f"[SUCCESS] gTPTunnel TEID修改: {hex(old_teid)} -> {hex(teid_value)}")
                    # 修改对应的全局变量
                    if pkt_num == 47:
                        upTEID1 = inc_hex(upTEID1)
                    else:
                        dnTEID1 = inc_hex(dnTEID1)
                    
                    modifications += 1
                
                # 只修改第一个找到的IP地址
                break
    
    # 策略2: 如果策略1没有找到，尝试查找ASN.1结构标记
    if modifications == 0:
        print("[GTP] 策略1未找到，尝试ASN.1结构搜索...")
        
        # 常见的ASN.1/3GPP结构标记
        asn1_patterns = [
            b'\x00\x06',         # 长度标记
            b'\x40\x06',         # gTPTunnel标记
            b'\x00\x00\x06',     # 扩展标记
            b'\x00\x03',         # 短标记
            b'\x06\x00',         # 反序标记
        ]
        
        for pattern in asn1_patterns:
            pos = data.find(pattern)
            if pos >= 0:
                print(f"[GTP] 找到ASN.1模式 {pattern.hex()} 在位置 {pos}")
                
                # 在模式附近搜索目标IP
                search_start = max(0, pos - 10)
                search_end = min(len(data) - 4, pos + 20)
                
                for search_pos in range(search_start, search_end):
                    if search_pos + 8 <= len(data):
                        if data[search_pos] == target_first_byte:
                            ip_candidate = data[search_pos:search_pos+4]
                            ip_str = '.'.join(str(b) for b in ip_candidate)
                            
                            print(f"[GTP] ASN.1搜索找到IP: {ip_str} 在位置 {search_pos}")
                              # 修改IP和TEID
                            new_ip_parts = [int(x) for x in ip_value.split('.')]
                            data[search_pos:search_pos+4] = new_ip_parts
                            print(f"[SUCCESS] ASN.1模式gTPTunnel IP修改: {ip_str} -> {ip_value}")
                            if pkt_num == 47:
                                upfIP1 = inc_ip(upfIP1)
                            else:
                                gnbIP1 = inc_ip(gnbIP1)
                            
                            modifications += 1
                            
                            # 修改TEID
                            teid_pos = search_pos + 4
                            if teid_pos + 4 <= len(data):
                                old_teid_bytes = data[teid_pos:teid_pos+4]
                                old_teid = int.from_bytes(old_teid_bytes, 'big')
                                new_teid_bytes = teid_value.to_bytes(4, 'big')
                                data[teid_pos:teid_pos+4] = new_teid_bytes
                                print(f"[SUCCESS] ASN.1模式gTPTunnel TEID修改: {hex(old_teid)} -> {hex(teid_value)}")
                                if pkt_num == 47:
                                    upTEID1 = inc_hex(upTEID1)
                                else:
                                    dnTEID1 = inc_hex(dnTEID1)
                                
                                modifications += 1
                              # 找到一个就够了
                            break
                
                if modifications > 0:
                    break
    
    if modifications == 0:
        print(f"[WARN] 报文{pkt_num}中未找到gTPTunnel字段（已尝试所有策略）")
    else:
        print(f"[INFO] 报文{pkt_num}的gTPTunnel字段修改完成，共修改{modifications}个字段")
    
    return modifications

# 主程序入口
if __name__ == "__main__":
    import argparse
    
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description='处理N11 PCAP文件中的HTTP/2帧，支持批量循环变量修改')
    parser.add_argument('-i', '--input', dest='input_file', default="pcap/N11_create_50p.pcap",
                        help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', default="pcap/N11_create_3k.pcap",
                        help='输出PCAP文件路径')
    parser.add_argument('-n', '--num', dest='num', type=int, default=100,
                        help='循环次数，生成报文组数')
    parser.add_argument('--ip-num', dest='ip_num', type=int, default=2000,
                        help='sip1/dip1/upfIP1/gnbIP1循环数量，默认2000')
    parser.add_argument('--port-num', dest='port_num', type=int, default=20000,
                        help='sport1/sport2/sport3循环数量，默认20000，+3递增')
    
    args = parser.parse_args()
    
    print("=== 程序启动 ===")
    print(f"输入文件: {args.input_file}")
    print(f"输出文件: {args.output_file}")
    print(f"循环次数: {args.num}")
    print(f"IP循环数量: {args.ip_num}")
    print(f"端口循环数量: {args.port_num}")
    print(f"初始变量值:")
    print(f"  sip1: {sip1}, dip1: {dip1}")
    print(f"  imsi1: {imsi1}")
    print(f"  imei14: {imei14}")
    print(f"  gpsi1: {gpsi1}")
    print(f"  PduAddr1: {PduAddr1}")
    print(f"  dnn1: {dnn1}")
    print(f"  tac1: {tac1}, cgi1: {cgi1}")
    print(f"  upfIP1: {upfIP1}, upTEID1: {hex(upTEID1)}")
    print(f"  gnbIP1: {gnbIP1}, dnTEID1: {hex(dnTEID1)}")
    print(f"  sport1: {sport1}, sport2: {sport2}, sport3: {sport3}")
    
    try:
        # 检查输入文件是否存在
        if not os.path.exists(args.input_file):
            print(f"错误：输入文件 {args.input_file} 不存在")
            sys.exit(1)
            
        # 调用主批处理函数
        main_batch(
            pcap_in=args.input_file,
            pcap_out=args.output_file,
            loop_num=args.num,
            ip_num=args.ip_num,
            port_num=args.port_num
        )
        
        print("=== 程序正常结束 ===")
        print(f"批量处理完成，输出文件: {args.output_file}")
        print("变量跳变说明:")
        print("  - sip1、dip1、upfIP1、gnbIP1: 按IP循环数量跳变")
        print("  - imsi1、imei14、gpsi1、PduAddr1、dnn1、tac1、cgi1、upTEID1、dnTEID1: +1递增")
        print("  - sport1、sport2、sport3: 按端口循环数量+3递增")
        
    except Exception as e:
        print(f"=== 程序异常结束: {e} ===")
        import traceback
        traceback.print_exc()
        sys.exit(1)