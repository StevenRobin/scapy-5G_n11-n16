from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re

# ========== 变量定义 ==========
# HTTP2/JSON/五元组相关变量
# HTTP2 authority
auth1 = "30.0.0.1"
# HTTP2 path中的context_ID
context_ID = "9000000001"
# JSON字段变量
imsi1 = "460012300000001"
pei1 = "8611101000000011"
gpsi1 = "8613900000001"
dnn1 = "dnn600000001"
ismfId1 = "000500000001"
upf1 = "10.0.0.1"
teid1 = "10000001"
upf2 = "20.0.0.1"
teid2 = "50000001"
ueIP1 = "100.0.0.1"
cgi1 = "010000001"
pduSessionId1 = "10000001"
# 五元组IP
sip1 = "30.0.0.1"
dip1 = "40.0.0.1"

# 五元组 IP 替换内容
IP_REPLACEMENTS = {
    "200.20.20.26": sip1,  # 原始IP到源IP的映射
    "200.20.20.25": dip1   # 原始IP到目的IP的映射
}

# 全局JSON字段映射表
JSON_FIELD_MAP = {
    "supi": f"imsi-{imsi1}",
    "pei": f"imeisv-{pei1}",
    "gpsi": f"msisdn-{gpsi1}",
    "dnn": dnn1,
    "ismfId": None,  # 特殊处理
    "icnTunnelInfo": {"ipv4Addr": upf1, "gtpTeid": teid1},
    "cnTunnelInfo": {"ipv4Addr": upf2, "gtpTeid": teid2},
    "ueIpv4Address": ueIP1,
    "nrCellId": cgi1,
    "uplink": "5000000000",
    "downlink": "5000000000",
    "ismfPduSessionUri": None  # 特殊处理
}

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

def modify_json_data(payload, modifications=None):
    """
    修改 JSON 数据中的目标字段，支持变量替换。
    """
    try:
        if not payload.strip():
            print("[跳过空数据段]")
            return None
        data = json.loads(payload)
        modified = False
        
        # 统一的变量替换映射
        global JSON_FIELD_MAP
        var_map = JSON_FIELD_MAP

        def recursive_modify(obj):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key == "ismfId":
                        # 只替换最后一段
                        parts = value.rsplit("-", 1)
                        if len(parts) == 2:
                            new_val = f"{parts[0]}-{ismfId1}"
                            if value != new_val:
                                obj[key] = new_val
                                modified = True
                    elif key == "ismfPduSessionUri":
                        # 替换host和最后数字
                        m = re.match(r"http://([\d.]+):\d+/(.+/)(\d+)", value)
                        if m:
                            new_val = f"http://{dip1}:80/{m.group(2)}{pduSessionId1}"
                            if value != new_val:
                                obj[key] = new_val
                                modified = True
                    elif key in var_map and var_map[key] is not None:
                        if value != var_map[key]:
                            obj[key] = var_map[key]
                            modified = True
                    elif key in ["icnTunnelInfo", "cnTunnelInfo"] and isinstance(value, dict):
                        for subk in ["ipv4Addr", "gtpTeid"]:
                            if value.get(subk) != var_map[key][subk]:
                                value[subk] = var_map[key][subk]
                                modified = True
                    elif isinstance(value, (dict, list)):
                        recursive_modify(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        recursive_modify(item)
        recursive_modify(data)
        return json.dumps(data, indent=None, separators=(',', ':')).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def process_http2_data_frame(frame_data, modifications=None):
    """处理 HTTP/2 DATA 帧中的多部分数据"""
    # 确保JSON字段总是被处理
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    # 按双 CRLF 分割获取 JSON 部分
                    segments = parts[i + 1].split(b"\r\n\r\n", 1)
                    if len(segments) == 2:
                        json_part = segments[1]
                        # 始终调用modify_json_data修改JSON字段
                        modified = modify_json_data(json_part)
                        if modified:
                            parts[i + 1] = segments[0] + b"\r\n\r\n" + modified
        return b''.join(parts)
    else:
        # 始终调用modify_json_data修改JSON字段
        modified = modify_json_data(frame_data)
        return modified if modified else frame_data

def process_packet(pkt, seq_diff, ip_replacements, original_length=None, new_length=None):
    """
    只做五元组IP替换和TCP序号/ack修正，seq_diff逻辑与5g_n16_mod_copilot05.py一致。
    original_length/new_length用于有payload包的diff累计。
    """
    if pkt.haslayer(IP):
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
        if original_length is not None and new_length is not None:
            diff = new_length - original_length
        # 只对SYN/FIN/RST以外的有效payload包做累计
        if has_payload and not (is_syn or is_fin or is_rst):
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]
            seq_diff[flow] += diff
        else:
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

# ========== HTTP2 Header定向修改辅助 ==========
def modify_http2_headers(header_block, modifications):
    """
    对HTTP2 header block进行HPACK解码，按需修改字段后再HPACK编码返回。
    modifications: dict，key为header名，value为新值。
    解码失败时直接返回原始header block。
    """
    decoder = Decoder()
    try:
        headers = decoder.decode(header_block)
    except Exception as e:
        print(f"[警告] HPACK解码失败，保留原header block: {e}")
        return header_block
    new_headers = []
    for k, v in headers:
        if k in modifications:
            new_headers.append((k, modifications[k]))
        else:
            new_headers.append((k, v))
    encoder = Encoder()
    try:
        return encoder.encode(new_headers)
    except Exception as e:
        print(f"[警告] HPACK编码失败，保留原header block: {e}")
        return header_block

# ========== path字段数字部分替换 ==========
def replace_path_context_id(path_value, new_context_id):
    """
    将path中的数字部分（如/xxx/1722077971/yyy）替换为new_context_id
    """
    return re.sub(r"(.*?/)(\d+)(/.*)", r"\1{}\3".format(new_context_id), path_value)

def process_http2_headers_frame(frame_data, new_path, new_authority):
    """
    参考 copilot07，定向修改 HTTP2 HEADERS 帧的 :path 和 :authority 字段。
    支持 name 和 value 为 bytes 或 str，自动类型对齐。
    增加详细调试打印。
    """
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        print("[DEBUG] HEADERS原始内容:")
        for i, (name, value) in enumerate(headers):
            print(f"  [{i}] name={name!r} type={type(name)}, value={value!r} type={type(value)}")
        modified = False
        new_headers = []
        for name, value in headers:
            n = name.decode() if isinstance(name, bytes) else name
            if n == ":path":
                v = new_path.encode() if isinstance(value, bytes) else new_path
                print(f"[DEBUG] 尝试修改 :path, 原值: {value!r} -> 新值: {v!r}")
                new_headers.append((name, v))
                modified = True
            elif n == ":authority":
                v = new_authority.encode() if isinstance(value, bytes) else new_authority
                print(f"[DEBUG] 尝试修改 :authority, 原值: {value!r} -> 新值: {v!r}")
                new_headers.append((name, v))
                modified = True
            else:
                new_headers.append((name, value))
        print("[DEBUG] HEADERS修改后:")
        for i, (name, value) in enumerate(new_headers):
            print(f"  [{i}] name={name!r} type={type(name)}, value={value!r} type={type(value)}")
        if modified:
            encoder = Encoder()
            new_frame_data = encoder.encode(new_headers)
            print(f"[DEBUG] HPACK编码后长度: {len(new_frame_data)}")
            return new_frame_data
        else:
            print("[DEBUG] 未做任何修改，返回原frame_data")
            return frame_data
    except Exception as e:
        print(f"Header处理错误: {str(e)}")
        return frame_data

# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"   # 输入 PCAP 文件路径
PCAP_OUT = "pcap/N16_1408.pcap"   # 输出 PCAP 文件路径

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)
modified_packets = []

seq_diff = {}

# 记录需要定向修改的报文序号（从1开始）
target_pkts = {9, 11, 13, 15}

for idx, pkt in enumerate(packets, 1):
    modified = False
    original_length = None
    new_length = None
    # 定向处理第9、11、13、15个报文
    if idx in target_pkts and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0
        new_payload = b''
        header_blocks = []
        for frame_idx in range(2):
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if frame_header is None or frame_data is None:
                break
            # HEADERS帧
            if frame_type == 0x1:
                if idx in {9, 13} and frame_idx == 0:
                    # 只对第9/13包首个HEADERS帧做定向替换
                    new_path = f"/nsmf-pdusession/v1/sm-contexts/{context_ID}/retrieve"
                    new_authority = auth1
                    new_header_block = process_http2_headers_frame(frame_data, new_path, new_authority)
                    frame_header.length = len(new_header_block)
                    new_payload += frame_header.build() + new_header_block
                    offset = frame_end
                    modified = True
                    continue
                decoder = Decoder()
                try:
                    headers = decoder.decode(frame_data)
                except Exception:
                    headers = []
                headers_dict = dict(headers)
                if idx in {11, 13, 15} and b'content-length' in headers_dict:
                    header_blocks.append((frame_header, frame_data, offset, frame_end))
                    offset = frame_end
                    continue
                new_payload += raw[offset:frame_end]
                offset = frame_end
        elif frame_type == 0x0:
                if frame_idx == 1:
                    modified_data = process_http2_data_frame(frame_data)
                    if modified_data is not None and len(modified_data) != len(frame_data):
                        frame_header.length = len(modified_data)
                        new_payload += frame_header.build() + modified_data
                        for h, hdata, hstart, hend in header_blocks:
                            decoder = Decoder()
                            try:
                                headers = decoder.decode(hdata)
                            except Exception:
                                headers = []
                            new_headers = []
                            for k, v in headers:
                                if k == b'content-length':
                                    new_headers.append((k, str(len(modified_data))))
                                else:
                                    new_headers.append((k, v))
                            encoder = Encoder()
                            new_hblock = encoder.encode(new_headers)
                            h.length = len(new_hblock)
                            new_payload = new_payload[:hstart] + h.build() + new_hblock + new_payload[hend:]
                        header_blocks.clear()
                        offset = frame_end
                        modified = True
                        continue
                new_payload += raw[offset:frame_end]
                offset = frame_end
            else:
                new_payload += raw[offset:frame_end]
                offset = frame_end
        new_payload += raw[offset:]
        original_length = len(raw)
        new_length = len(new_payload)
        if modified:
            pkt[Raw].load = new_payload
    # 所有包都统一调用process_packet做IP和TCP修正
    process_packet(pkt, seq_diff, IP_REPLACEMENTS, original_length, new_length)
    modified_packets.append(pkt)

print(f"保存修改后的 PCAP 到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)