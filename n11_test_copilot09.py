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
    "gpsi": f"msisdn-{gpsi1}",    "dnn": dnn1,
    "tac": tac1,
    "nrCellId": cgi1,
    "smContextStatusUri": f"http://{sip1}/ntf-service/v1/nsmf-notify/0/pdusession-smcontextsts"
}

PCAP_IN = "pcap/N11_create_50p_portX.pcap"
PCAP_OUT = "pcap/N11_create_1001.pcap"

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
                    # 特殊处理smContextStatusUri字段，替换URL中的host部分
                    if lkey == "smcontextstatusuri" and isinstance(value, str):
                        print(f"[DEBUG] 发现 smContextStatusUri 字段: {value}")
                        # 使用正则表达式替换URL中的host部分为sip1
                        new_value = re.sub(r'http://[^/]+', f'http://{sip1}', value)
                        if new_value != value:
                            print(f"[+] 修改JSON字段 {key}: {value} -> {new_value}")
                            obj[key] = new_value
                            modified = True
                        else:
                            print(f"[INFO] smContextStatusUri 字段无需修改: {value}")
                    else:
                        # 原有的字段匹配逻辑
                        for target in modifications:
                            if target.lower() == lkey:
                                print(f"[+] 修改JSON字段 {key} ({value}) -> {modifications[target]}")
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
                    print(f"[DEBUG] 精确处理第{pkt_idx+1}号报文的DATA帧内容")
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
                    print(f"[DEBUG] 精确重建第{pkt_idx+1}号报文的HEADERS帧")
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
            ("content-type", "multipart/related; boundary=++Boundary"),  # 修复：使用multipart/related
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("accept", "application/json"),
            ("user-agent", "AMF"),
        ]
        print(f"[精确重建] pkt12 HEADERS: {headers}")
        return encoder.encode(headers)
    elif pkt_idx == 45:  # 第46个报文
        headers = [
            (":status", "201"),
            ("content-type", "multipart/related; boundary=++Boundary"),  # 修复：使用multipart/related
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
            ("content-type", "multipart/related; boundary=++Boundary"),  # 修复：使用multipart/related
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("user-agent", "SMF"),
        ]
        print(f"[精确重建] pkt47 HEADERS: {headers}")
        return encoder.encode(headers)
    elif pkt_idx == 48:  # 第49个报文
        headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", auth1),
            (":path", f"/nsmf-pdusession/v1/sm-contexts/imsi-{imsi1}-5/modify"),
            ("content-type", "multipart/related; boundary=++Boundary"),  # 修复：使用multipart/related
            ("content-length", str(new_content_length) if new_content_length else "0"),
            ("accept", "application/json"),
            ("user-agent", "SMF"),  # 保持原始值SMF
        ]
        print(f"[精确重建] pkt49 HEADERS: {headers}")
        return encoder.encode(headers)
    else:
        return None

# 函数已删除，因为报文中只有一个HEADERS帧

def process_http2_data_frame_precise(pkt_idx, frame_data, fields):
    """
    针对关键报文（12、47、49）DATA帧的精确处理，严格保持MIME结构
    """
    print(f"[精确重建] pkt{pkt_idx+1} DATA帧处理，原始长度: {len(frame_data)}")
    
    # 只处理含boundary的multipart
    if pkt_idx in (11, 46, 48) and b"--++Boundary" in frame_data:
        # 完全重建MIME结构，确保格式正确
        return rebuild_mime_structure(frame_data, fields, pkt_idx)
    else:
        # 如果不是multipart格式，使用标准处理
        return process_http2_data_frame(frame_data, fields)

def rebuild_mime_structure(frame_data, fields, pkt_idx):
    """重建完整的MIME结构，确保Wireshark能正确解析"""
    
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
                    headers_section += f"\r\nContent-Id:{content_id}".encode()
                
                # 修改JSON内容
                modified_json = modify_json_data(body_section, fields)
                if modified_json:
                    body_section = modified_json
                    print(f"[+] 成功修改报文{pkt_idx+1}的JSON内容")
            else:
                # 非JSON部分，确保有Content-Id
                if b'Content-Id:' not in headers_section:
                    content_id = f"Part{i}"
                    headers_section += f"\r\nContent-Id:{content_id}".encode()
            
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
    
    print(f"[重建] 新MIME结构长度: {len(result)} 字节")
    return result

def process_one_batch(original_packets, batch_idx, total_batches, target_fields):
    print(f"[BATCH] 处理第{batch_idx+1}/{total_batches}批，共{len(original_packets)}包")
    pkt_http2_info = batch_collect_targets(original_packets)
    all_new_payloads = batch_modify_targets(pkt_http2_info, target_fields)
    new_packets = update_packets(original_packets, all_new_payloads)
    return new_packets

def main_batch(
    pcap_in=PCAP_IN,
    pcap_out=PCAP_OUT,
    loop_num=1,
    batch_size=50,
    target_fields=TARGET_FIELDS
):
    print("=== 程序开始运行 ===")
    print(f"输入文件: {pcap_in}")
    print(f"输出文件: {pcap_out}")
    print(f"循环次数: {loop_num}")
    print(f"批量大小: {batch_size}")
    
    try:
        print(f"开始批量处理文件 {pcap_in}")
        print("正在读取PCAP文件...")
        original_packets = rdpcap(pcap_in)
        print(f"成功读取PCAP文件，包含 {len(original_packets)} 个数据包")
        
        total_batches = (loop_num + batch_size - 1) // batch_size
        print(f"将处理 {total_batches} 个批次")
        
        all_packets = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
            for batch_idx in range(total_batches):
                start = batch_idx * batch_size
                end = min((batch_idx + 1) * batch_size, loop_num)
                # 每批复制原始包
                batch_packets = [copy.deepcopy(pkt) for pkt in original_packets]
                futures.append(executor.submit(
                    process_one_batch, batch_packets, batch_idx, total_batches, target_fields
                ))
            for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="批量进度"):
                batch_result = f.result()
                all_packets.extend(batch_result)
        print(f"保存所有批量结果到 {pcap_out}")
        
        # 修复数据包链路层类型问题
        fixed_packets = []
        for pkt in all_packets:
            if pkt.__class__.__name__ == 'Raw':
                # 如果是Raw包，包装为Ether帧以避免写入错误
                eth_pkt = Ether()/pkt
                fixed_packets.append(eth_pkt)
            else:
                fixed_packets.append(pkt)
        
        print(f"修复了 {len([p for p in all_packets if p.__class__.__name__ == 'Raw'])} 个Raw数据包的链路层类型")
        wrpcap(pcap_out, fixed_packets)
        print(f"全部批量处理完成，总输出包数: {len(fixed_packets)}")
        
    except Exception as e:
        print(f"程序执行出错: {e}")
        import traceback
        traceback.print_exc()

def debug_packet_frames(pkt_idx, pkt_info):
    """调试函数：打印包中的HTTP/2帧信息"""
    if pkt_idx in (11, 46, 48):  # 关键报文调试
        print(f"[调试] 第{pkt_idx+1}号报文包含{len(pkt_info)}个HTTP/2帧:")
        for i, entry in enumerate(pkt_info):
            if entry['type'] == 'headers':
                print(f"  帧{i}: HEADERS帧 (长度: {len(entry['data'])}字节)")
            elif entry['type'] == 'data':
                print(f"  帧{i}: DATA帧 (长度: {len(entry['data'])}字节)")

def validate_http2_frame_structure(raw_data, pkt_idx):
    """验证HTTP/2帧结构的有效性"""
    frames = extract_http2_frames(raw_data)
    headers_count = sum(1 for f in frames if f['type'] == 0x1)
    data_count = sum(1 for f in frames if f['type'] == 0x0)
    
    if pkt_idx in (11, 46, 48):  # 关键报文应该有一个HEADERS帧和一个DATA帧
        if headers_count != 1:
            print(f"[警告] 第{pkt_idx+1}号报文应有1个HEADERS帧，但发现了{headers_count}个")
            return headers_count > 0  # 至少有一个头才能继续
        
        if data_count != 1:
            print(f"[警告] 第{pkt_idx+1}号报文应有1个DATA帧，但发现了{data_count}个")
    
    return True

# 主程序入口
if __name__ == "__main__":
    print("=== 程序启动 ===")
    try:
        main_batch()
        print("=== 程序正常结束 ===")
    except Exception as e:
        print(f"=== 程序异常结束: {e} ===")
        import traceback
        traceback.print_exc()