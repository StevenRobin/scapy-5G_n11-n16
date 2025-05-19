from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Encoder, Decoder
import json
import re

# 配置参数
TARGET_FIELDS = {
    "supi": "imsi-460030100000022",
    "pei": "imeisv-1031014000012222",
    "gpsi": "msisdn-15910012222"
}
ORIGINAL_IMSI = "imsi-460030100000000"
MODIFIED_IMSI = "imsi-460030100000022"
PCAP_IN = "pcap/N11_create_50p.pcap"
PCAP_OUT = "pcap/N11_106.pcap"

# 新增参数：匹配第49个报文的path前缀和后缀
MODIFY_PATH_PREFIX = "/nsmf-pdusession/v1/sm-contexts/"
MODIFY_PATH_SUFFIX = "-5/modify"

# 在文件开头添加全局变量
EXTRACTED_SUPI = None

# 自定义HTTP/2帧头解析
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
    """解析HTTP/2帧头部"""
    try:
        if offset + 9 > len(raw):
            return None, None, None, None, len(raw)
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
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

def modify_json_data(payload, fields):
    """修改JSON数据中的目标字段"""
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

# 修改process_http2_headers_frame函数，添加pkt_index参数来识别第46个报文
def process_http2_headers_frame(frame_data, original_imsi, modified_imsi, modify_path_only=False, pkt_index=None):
    """
    处理HTTP/2 HEADERS帧
    modify_path_only: True时，仅对匹配指定path的包做imsi的替换
    pkt_index: 当前包的索引，用于特殊处理第46个报文
    """
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        new_headers = []
        modified = False
        
        # 特殊处理第46个报文 (索引为45)
        if pkt_index == 45:
            for name, value in headers:
                if name.lower() == "location":
                    print(f"[*] 第46个报文的location字段: {value}")
                    # 保存提取的supi值（如果需要后续使用）
                    if value.startswith("http://123.1.1.10/nsmf-pdusession/v1/sm-contexts/"):
                        parts = value.split("-5")
                        if parts and len(parts) > 0:
                            extracted_supi = parts[0].split("/sm-contexts/")[1]
                            print(f"[*] 提取的supi值: {extracted_supi}")
                            # 可以将提取的supi保存为全局变量，以便在处理第49个报文时使用
                            global EXTRACTED_SUPI
                            EXTRACTED_SUPI = extracted_supi
        
        # 原有处理逻辑
        for name, value in headers:
            # 针对path字段: 只改第49包的 /nsmf-pdusession/v1/sm-contexts/imsi-...-5/modify
            if modify_path_only and name.lower() == ":path":
                if value.startswith(MODIFY_PATH_PREFIX) and value.endswith(MODIFY_PATH_SUFFIX):
                    mid = value[len(MODIFY_PATH_PREFIX):-len(MODIFY_PATH_SUFFIX)]
                    if mid.startswith("imsi-"):
                        # 使用从第46个报文提取的supi（如果有）
                        supi_to_use = EXTRACTED_SUPI if EXTRACTED_SUPI else MODIFIED_IMSI
                        new_value = MODIFY_PATH_PREFIX + supi_to_use + MODIFY_PATH_SUFFIX
                        print(f"[+] 修改第49包 :path 字段: {value} -> {new_value}")
                        new_headers.append((name, new_value))
                        modified = True
                    else:
                        new_headers.append((name, value))
                else:
                    new_headers.append((name, value))
            # 原有功能: 修改其它imsi路径
            elif not modify_path_only and name.lower() == ":path" and original_imsi in value:
                new_value = value.replace(original_imsi, modified_imsi)
                print(f"[+] 修改URL路径: {value} -> {new_value}")
                new_headers.append((name, new_value))
                modified = True
            # location字段imsi替换，不改pduSessionId
            elif not modify_path_only and name.lower() == "location":
                LOCATION_HEADER_PREFIX = "http://123.1.1.10/nsmf-pdusession/v1/sm-contexts/"
                LOCATION_HEADER_SUFFIX = "-5"
                if value.startswith(LOCATION_HEADER_PREFIX) and value.endswith(LOCATION_HEADER_SUFFIX):
                    mid = value[len(LOCATION_HEADER_PREFIX):-len(LOCATION_HEADER_SUFFIX)]
                    if mid.startswith("imsi-"):
                        new_value = LOCATION_HEADER_PREFIX + MODIFIED_IMSI + LOCATION_HEADER_SUFFIX
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

def process_packet(pkt, seq_diff, modifications, original_imsi, modified_imsi, pkt_index=None):
    """
    处理每个数据包
    pkt_index: 当前包索引（用于特殊处理第49报文）
    """
    if pkt.haslayer(IP):
        pass

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

        if has_payload and not (is_syn or is_fin or is_rst):
            raw = bytes(pkt[Raw].load)
            offset = 0
            new_payload = b''
            while offset < len(raw):
                if offset + 9 > len(raw):
                    new_payload += raw[offset:]
                    offset = len(raw)
                    break
                frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
                if frame_header is None:
                    break
                # 特殊：第49个包的:path
                if pkt_index == 48 and frame_type == 0x1:
                    modified_frame_data = process_http2_headers_frame(
                        frame_data, original_imsi, modified_imsi, modify_path_only=True, pkt_index=pkt_index
                    )
                    if modified_frame_data:
                        frame_len = len(modified_frame_data)
                        frame_header.length = frame_len
                        new_payload += frame_header.build() + modified_frame_data
                        offset = frame_end
                        continue
                # 普通模式
                if frame_type == 0x1:
                    modified_frame_data = process_http2_headers_frame(
                        frame_data, original_imsi, modified_imsi, 
                        modify_path_only=(pkt_index == 48), # 第49个包特殊处理
                        pkt_index=pkt_index
                    )
                    if modified_frame_data:
                        frame_len = len(modified_frame_data)
                        frame_header.length = frame_len
                        new_payload += frame_header.build() + modified_frame_data
                        offset = frame_end
                        continue
                if frame_type == 0x0:
                    modified_frame_data = process_http2_data_frame(frame_data, modifications)
                    if modified_frame_data:
                        frame_len = len(modified_frame_data)
                        frame_header.length = frame_len
                        new_payload += frame_header.build() + modified_frame_data
                        offset = frame_end
                        continue
                new_payload += raw[offset:frame_end]
                offset = frame_end
            original_length = len(raw)
            new_length = len(new_payload)
            diff = new_length - original_length
            pkt[Raw].load = new_payload

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

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified_packets = []

seq_diff = {}

for idx, pkt in enumerate(packets):
    if TCP in pkt:
        process_packet(pkt, seq_diff, TARGET_FIELDS, ORIGINAL_IMSI, MODIFIED_IMSI, pkt_index=idx)
    modified_packets.append(pkt)

# 检查是否成功提取了第46个报文的location字段
if EXTRACTED_SUPI:
    print(f"成功提取第46个报文的supi值: {EXTRACTED_SUPI}")
else:
    print("未能提取第46个报文的supi值")

print(f"保存修改到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)