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
        # 确保payload是字符串
        if isinstance(payload, bytes):
            payload_str = payload.decode('utf-8', errors='ignore')
        else:
            payload_str = payload
            
        # 跳过空数据段
        if not payload_str.strip():
            print("[跳过空数据段]")
            return None
            
        data = json.loads(payload_str)
        modified = False

        def recursive_modify(obj, modifications):
            """递归修改嵌套 JSON 对象"""
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in list(obj.items()):  # 使用list()创建副本，避免在迭代时修改
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
        
        if modified:
            result = json.dumps(data, separators=(',', ':'))
            return result.encode('utf-8')
        return None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def calculate_exact_json_length(frame_data):
    """计算DATA帧中JSON数据的准确长度"""
    try:
        # 检查是否是多部分内容
        if b"--++Boundary" in frame_data:
            parts = re.split(br'(--\+\+Boundary)', frame_data)
            for i in range(len(parts)):
                if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                    if b"Content-Type:application/json" in parts[i + 1] or b"Content-Type: application/json" in parts[i + 1]:
                        segments = parts[i + 1].split(b"\r\n\r\n", 1)
                        if len(segments) == 2:
                            json_part = segments[1]
                            return len(json_part)
            return len(frame_data)  # 如果没有找到JSON部分，返回整个帧的长度
        else:
            # 尝试作为纯JSON解析
            if frame_data and frame_data.strip():
                return len(frame_data)
            return 0
    except Exception as e:
        print(f"计算JSON长度错误: {str(e)}")
        return len(frame_data)

def process_http2_data_frame(frame_data, modifications):
    """处理 HTTP/2 DATA 帧中的多部分数据，并返回修改后的数据和实际的JSON数据长度"""
    json_length = 0
    modified_data = None

    # 多部分边界检测
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1] or b"Content-Type: application/json" in parts[i + 1]:
                    segments = parts[i + 1].split(b"\r\n\r\n", 1)
                    if len(segments) == 2:
                        json_part = segments[1]
                        modified = modify_json_data(json_part, modifications)
                        if modified:
                            parts[i + 1] = segments[0] + b"\r\n\r\n" + modified
                            json_length = len(modified)  # 使用修改后的JSON长度
                        else:
                            json_length = len(json_part)  # 使用原始JSON长度
        modified_data = b''.join(parts)
    else:
        try:
            # 尝试解析为JSON
            if frame_data.strip():
                modified = modify_json_data(frame_data, modifications)
                if modified:
                    modified_data = modified
                    json_length = len(modified)  # 使用修改后的JSON长度
                else:
                    modified_data = frame_data
                    json_length = len(frame_data)  # 使用原始JSON长度
        except Exception as e:
            print(f"JSON解析错误: {str(e)}")
            modified_data = frame_data
            json_length = len(frame_data)

    return modified_data, json_length

def process_http2_headers_frame(frame_data, context_num, exact_data_length=None):
    """
    处理 HTTP/2 HEADERS 帧，修改 path 和 authority 字段，更新 content-length
    如果提供了exact_data_length，则使用该值作为content-length的值
    """
    try:
        decoder = Decoder()
        encoder = Encoder()
        
        try:
            headers = decoder.decode(frame_data)
        except Exception as e:
            print(f"HPACK解码错误: {str(e)}")
            return frame_data, None
            
        modified = False
        new_headers = []
        content_length_value = None
        has_content_length = False

        # 第一遍：收集除content-length外的所有headers
        for name, value in headers:
            # 确保name和value都是字符串
            if isinstance(name, bytes):
                name = name.decode('utf-8', errors='ignore')
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='ignore')
                
            if name.lower() == "content-length":
                content_length_value = value  # 记录原始content-length值
                has_content_length = True
                continue  # 暂时忽略content-length字段
                
            if name == ":path":
                new_path = f"/nsmf-pdusession/v1/sm-contexts/{context_num}/retrieve"
                print(f"[+] 修改 header {name}: {value} -> {new_path}")
                new_headers.append((name, new_path))
                modified = True
            elif name == ":authority":
                new_authority = "smf.smf"
                print(f"[+] 修改 header {name}: {value} -> {new_authority}")
                new_headers.append((name, new_authority))
                modified = True
            else:
                new_headers.append((name, value))

        # 如果提供了精确的DATA帧长度，则使用它作为content-length
        if has_content_length and exact_data_length is not None and exact_data_length > 0:
            print(f"[+] 更新 content-length: {content_length_value} -> {exact_data_length}")
            new_headers.append(("content-length", str(exact_data_length)))
            content_length_value = str(exact_data_length)
            modified = True

        # 返回修改后的头部和content-length值
        if modified:
            try:
                return encoder.encode(new_headers), content_length_value
            except Exception as e:
                print(f"HPACK编码错误: {str(e)}")
                return frame_data, content_length_value
        return frame_data, content_length_value
    except Exception as e:
        print(f"Header处理错误: {str(e)}")
        return frame_data, None

def handle_pdu_session_frames(raw, context_num, modifications):
    """
    专门处理PDU会话创建请求的帧
    这是针对第13个报文的特殊处理，确保content-length与DATA帧长度一致
    """
    try:
        # 初始化变量
        new_payload = b''
        offset = 0
        data_frame_length = None
        modified_data = None
        
        # 首先查找所有帧
        frame_info = []
        current_offset = 0
        
        while current_offset + 9 <= len(raw):
            try:
                frame_header = HTTP2FrameHeader(raw[current_offset:current_offset + 9])
                frame_type = frame_header.type
                frame_len = frame_header.length
                frame_data = raw[current_offset + 9:current_offset + 9 + frame_len]
                
                frame_info.append({
                    'offset': current_offset,
                    'type': frame_type,
                    'length': frame_len,
                    'data': frame_data,
                    'header': frame_header
                })
                
                current_offset += 9 + frame_len
                if current_offset >= len(raw):
                    break
            except Exception as e:
                print(f"帧解析错误: {str(e)}")
                current_offset += 9  # 尝试跳过这个可能损坏的帧
                if current_offset >= len(raw):
                    break
        
        # 处理DATA帧
        data_frame = None
        for frame in frame_info:
            if frame['type'] == 0x0:  # DATA帧
                data_frame = frame
                modified_data, _ = process_http2_data_frame(frame['data'], modifications)
                if modified_data:
                    data_frame_length = len(modified_data)
                    print(f"[+] PDU会话DATA帧: 原长度={frame['length']}, 修改后长度={data_frame_length}")
                else:
                    data_frame_length = len(frame['data'])
                break
        
        # 对第13个报文的content-length特殊处理，强制设置为702
        if data_frame_length is None:
            # 如果没有找到DATA帧，使用默认值
            data_frame_length = 702
            print(f"[!] 未找到DATA帧，使用固定长度: {data_frame_length}")
        
        # 现在处理所有帧
        for frame in frame_info:
            if frame['type'] == 0x1:  # HEADERS帧
                # 检查是否包含content-length
                if b"content-length" in frame['data'].lower():
                    # 使用准确的DATA帧长度
                    processed_headers, _ = process_http2_headers_frame(frame['data'], context_num, data_frame_length)
                    frame_header = frame['header']
                    frame_header.length = len(processed_headers)
                    new_payload += bytes(frame_header.build()) + processed_headers
                else:
                    # 普通的HEADERS帧
                    processed_headers, _ = process_http2_headers_frame(frame['data'], context_num, None)
                    if processed_headers != frame['data']:
                        frame_header = frame['header']
                        frame_header.length = len(processed_headers)
                        new_payload += bytes(frame_header.build()) + processed_headers
                    else:
                        # 保持原样
                        frame_header = frame['header']
                        new_payload += raw[frame['offset']:frame['offset'] + 9 + frame['length']]
            elif frame['type'] == 0x0:  # DATA帧
                if modified_data:
                    frame_header = frame['header']
                    frame_header.length = data_frame_length
                    new_payload += bytes(frame_header.build()) + modified_data
                else:
                    # 保持原样
                    frame_header = frame['header']
                    new_payload += raw[frame['offset']:frame['offset'] + 9 + frame['length']]
            else:
                # 其他类型帧保持原样
                new_payload += raw[frame['offset']:frame['offset'] + 9 + frame['length']]
                
        print(f"[特殊处理] PDU会话创建请求处理完成，DATA帧长度: {data_frame_length}")
        return new_payload
    except Exception as e:
        print(f"PDU会话帧处理错误: {str(e)}")
        return raw

def detect_special_response(raw):
    """检测是否为特殊的响应报文（需要修复content-length与DATA帧不匹配问题）"""
    try:
        # 检测是否存在content-length与DATA帧不匹配的情况
        content_length_value = None
        data_frame_length = None
        
        # 第一遍：提取header中的content-length和DATA帧长度
        offset = 0
        while offset + 9 <= len(raw):
            frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
            frame_type = frame_header.type
            frame_len = frame_header.length
            frame_data = raw[offset + 9:offset + 9 + frame_len]
            
            if frame_type == 0x1:  # HEADERS帧
                # 解析HEADERS帧查找content-length
                try:
                    decoder = Decoder()
                    headers = decoder.decode(frame_data)
                    for name, value in headers:
                        if isinstance(name, bytes):
                            name = name.decode('utf-8', errors='ignore')
                        if isinstance(value, bytes):
                            value = value.decode('utf-8', errors='ignore')
                            
                        if name.lower() == 'content-length':
                            content_length_value = int(value)
                            break
                except:
                    pass
            elif frame_type == 0x0:  # DATA帧
                data_frame_length = frame_len
            
            offset += 9 + frame_len
            if offset >= len(raw):
                break
        
        # 如果发现content-length与DATA帧长度不匹配，标记为特殊报文
        if content_length_value is not None and data_frame_length is not None:
            if content_length_value != data_frame_length:
                print(f"[检测] 发现特殊响应报文: content-length={content_length_value}, DATA帧长度={data_frame_length}")
                return True, data_frame_length
                
        return False, None
    except:
        return False, None

def fix_special_response(raw, actual_data_length):
    """修复特殊响应报文中的content-length与DATA帧不匹配问题"""
    try:
        new_payload = b''
        offset = 0
        
        while offset + 9 <= len(raw):
            frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
            frame_type = frame_header.type
            frame_len = frame_header.length
            frame_data = raw[offset + 9:offset + 9 + frame_len]
            
            if frame_type == 0x1:  # HEADERS帧
                # 检查是否包含content-length
                if b"content-length" in frame_data.lower():
                    # 解析并修改HEADERS帧
                    try:
                        decoder = Decoder()
                        encoder = Encoder()
                        headers = decoder.decode(frame_data)
                        new_headers = []
                        
                        for name, value in headers:
                            if isinstance(name, bytes):
                                name = name.decode('utf-8', errors='ignore')
                            if isinstance(value, bytes):
                                value = value.decode('utf-8', errors='ignore')
                                
                            if name.lower() == 'content-length':
                                print(f"[修复] content-length: {value} -> {actual_data_length}")
                                new_headers.append((name, str(actual_data_length)))
                            else:
                                new_headers.append((name, value))
                                
                        # 编码新头部
                        encoded_headers = encoder.encode(new_headers)
                        frame_header.length = len(encoded_headers)
                        new_payload += bytes(frame_header.build()) + encoded_headers
                    except Exception as e:
                        print(f"修复HEADERS帧失败: {str(e)}")
                        new_payload += raw[offset:offset + 9 + frame_len]
                else:
                    # 其他HEADERS帧保持不变
                    new_payload += raw[offset:offset + 9 + frame_len]
            else:
                # 其他类型帧保持不变
                new_payload += raw[offset:offset + 9 + frame_len]
                
            offset += 9 + frame_len
            if offset >= len(raw):
                break
                
        return new_payload
    except Exception as e:
        print(f"修复特殊响应报文失败: {str(e)}")
        return raw

def detect_pdu_session_post(raw):
    """检测是否为PDU会话创建请求（第13个报文）"""
    try:
        if len(raw) < 100:
            return False
            
        # 查看原始数据中是否包含pdu-sessions关键字
        if b"pdu-sessions" in raw:
            # 进一步确认是POST请求
            offset = 0
            while offset + 9 <= len(raw):
                frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
                frame_type = frame_header.type
                frame_len = frame_header.length
                
                if frame_type == 0x1:  # HEADERS帧
                    frame_data = raw[offset + 9:offset + 9 + frame_len]
                    if b":method" in frame_data and b"POST" in frame_data and b"pdu-sessions" in frame_data:
                        return True
                
                offset += 9 + frame_len
                if offset >= len(raw):
                    break
                    
        return False
    except:
        return False

def process_packet(pkt, modifications, seq_diff, ip_replacements, context_num):
    """
    对 TCP 包内部的 HTTP/2 数据帧进行处理：
    1. 解析所有 HTTP/2 帧，修改 HEADERS 帧中的 path 和 authority。
    2. 对 DATA 帧进行 JSON 数据修改。
    3. 修改五元组 IP 地址对。
    4. 追加未解析的剩余数据，防止丢失。
    5. 根据包内负载变化计算偏移量，累加调整 TCP 序号。
    6. 删除校验和字段，让 Scapy 自动重新生成。
    """
    if pkt.haslayer(IP):
        # 修改五元组 IP 地址对
        if pkt[IP].src in ip_replacements:
            print(f"[+] 替换源IP {pkt[IP].src} -> {ip_replacements[pkt[IP].src]}")
            pkt[IP].src = ip_replacements[pkt[IP].src]
        if pkt[IP].dst in ip_replacements:
            print(f"[+] 替换目的IP {pkt[IP].dst} -> {ip_replacements[pkt[IP].dst]}")
            pkt[IP].dst = ip_replacements[pkt[IP].dst]

    if pkt.haslayer(TCP):
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
        new_payload = None

        # 只对SYN/FIN/RST以外的有效payload包做处理
        if has_payload and not (is_syn or is_fin or is_rst):
            raw = bytes(pkt[Raw].load)
            
            # 特殊检测：是否为PDU会话创建请求（第13个报文）
            is_pdu_session = detect_pdu_session_post(raw)
            if is_pdu_session:
                print(f"[检测] 发现PDU会话创建请求报文，进行特殊处理")
                new_payload = handle_pdu_session_frames(raw, context_num, modifications)
            else:
                # 检查是否为特殊响应报文（第15个报文等）
                is_special, actual_data_length = detect_special_response(raw)
                if is_special and actual_data_length:
                    print(f"[检测] 发现特殊响应报文，进行特殊处理")
                    new_payload = fix_special_response(raw, actual_data_length)
                else:
                    # 常规HTTP/2报文处理
                    offset = 0
                    new_payload = b''
                    data_frames = []
                    exact_data_length = None
                    headers_frames = []
                    
                    # 第一遍：收集所有帧信息
                    current_offset = 0
                    while current_offset + 9 <= len(raw):
                        frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, current_offset)
                        if frame_header is None:
                            break
                            
                        if frame_type == 0x0:  # DATA帧
                            data_frames.append((frame_data, frame_len, current_offset))
                        elif frame_type == 0x1:  # HEADERS帧
                            headers_frames.append((frame_data, frame_len, current_offset))
                            
                        current_offset = frame_end
                    
                    # 如果有DATA帧，先处理它们以确定准确的长度
                    if data_frames:
                        frame_data, frame_len, _ = data_frames[0]
                        modified_data, json_length = process_http2_data_frame(frame_data, modifications)
                        
                        # 确定准确的数据长度
                        if modified_data:
                            exact_data_length = len(modified_data)
                        else:
                            exact_data_length = calculate_exact_json_length(frame_data)
                            if exact_data_length == 0 or exact_data_length > len(frame_data):
                                exact_data_length = frame_len
                    
                    # 第二遍：处理所有帧
                    while offset + 9 <= len(raw):
                        frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
                        if frame_header is None:
                            # 处理剩余数据
                            new_payload += raw[offset:]
                            offset = len(raw)
                            break
                            
                        if frame_type == 0x1:  # HEADERS帧
                            # 使用精确的数据长度处理HEADERS帧
                            modified_headers, content_length = process_http2_headers_frame(
                                frame_data, context_num, exact_data_length)
                                
                            if modified_headers != frame_data:
                                frame_len = len(modified_headers)
                                frame_header.length = frame_len
                                new_payload += bytes(frame_header.build()) + modified_headers
                                offset = frame_end
                                continue
                        elif frame_type == 0x0:  # DATA帧
                            # 处理DATA帧
                            modified_data, _ = process_http2_data_frame(frame_data, modifications)
                            
                            if modified_data and modified_data != frame_data:
                                frame_len = len(modified_data)
                                frame_header.length = frame_len
                                new_payload += bytes(frame_header.build()) + modified_data
                                exact_data_length = frame_len  # 更新精确数据长度
                                offset = frame_end
                                continue
                        
                        # 默认处理：保留原始帧
                        new_payload += raw[offset:frame_end]
                        offset = frame_end
                        
                    # 检查HEADERS帧的content-length是否与DATA帧长度一致
                    if exact_data_length is not None:
                        print(f"[调试] 报文({pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}): DATA帧实际长度={exact_data_length}")

            # 更新数据包负载
            if new_payload and new_payload != raw:
                original_length = len(raw)
                new_length = len(new_payload)
                diff = new_length - original_length
                pkt[Raw].load = new_payload

            # 修正seq/ack
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]
            # 只有有payload非SYN/FIN/RST才累计
            seq_diff[flow] += diff

        else:
            # 其它包（SYN/FIN/RST/无payload）只修正seq/ack，不累计
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]

        # 清空校验和和长度，交给 scapy 重算
        if hasattr(pkt[IP], 'chksum'):
            del pkt[IP].chksum
        if hasattr(pkt[TCP], 'chksum'):
            del pkt[TCP].chksum
        if hasattr(pkt[IP], 'len'):
            del pkt[IP].len

        pkt.wirelen = len(pkt)
        pkt.caplen = pkt.wirelen

# ---------------------- 主处理流程 ----------------------
def main():
    PCAP_IN = "pcap/N16_create_16p.pcap"   # 输入 PCAP 文件路径
    PCAP_OUT = "pcap/N16_164.pcap"   # 输出 PCAP 文件路径

    # JSON 字段修改内容
    MODIFICATIONS = {
        "supi": "imsi-460012300000001",
        "pei": "imeisv-8611101000000011",
        "gpsi": "msisdn-8613900000001",
        "dnn": "dnn12345",
        "ismfId": "c251849c-681e-48ba-918b-000010000001",
        "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
        "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "50000001"},
        "ueIpv4Address": "100.0.0.1",
        "nrCellId": "010000001",
        "uplink": "5000000000",
        "downlink": "5000000000",
        "ismfPduSessionUri": "http://30.0.0.1:80/nsmf-pdusession/v1/pdu-sessions/10000001"  # Updated ID
    }

    # 五元组 IP 替换内容
    IP_REPLACEMENTS = {
        "200.20.20.26": "30.0.0.1",
        "200.20.20.25": "40.0.0.1"
    }

    print(f"开始处理文件 {PCAP_IN}")
    
    try:
        packets = rdpcap(PCAP_IN)
        print(f"成功读取 {len(packets)} 个数据包")
    except Exception as e:
        print(f"读取PCAP文件失败: {str(e)}")
        return

    modified_packets = []

    # 保存每个流累计的 TCP 序号偏移量
    seq_diff = {}
    # 初始化context编号
    context_num = 1000000001

    # 处理每个数据包
    for pkt in packets:
        try:
            if TCP in pkt or Raw in pkt:
                process_packet(pkt, MODIFICATIONS, seq_diff, IP_REPLACEMENTS, context_num)
                # 每处理一个包，context_num递增
                context_num += 1
            modified_packets.append(pkt)
        except Exception as e:
            print(f"数据包处理错误: {str(e)}")
            modified_packets.append(pkt)  # 保留原始包

    print(f"保存修改后的 PCAP 到 {PCAP_OUT}")
    try:
        wrpcap(PCAP_OUT, modified_packets)
        print("PCAP文件保存成功")
    except Exception as e:
        print(f"保存PCAP文件失败: {str(e)}")

if __name__ == "__main__":
    main() 