from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re
import os
import logging

# 配置日志
import threading
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s',
    handlers=[
        logging.FileHandler("n16_pcap_process.log", mode="w"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger_lock = threading.Lock()  # 用于确保日志输出不会混淆

def safe_log(level, message):
    """线程安全的日志记录"""
    with logger_lock:
        if level == "debug":
            logger.debug(message)
        elif level == "info":
            logger.info(message)
        elif level == "warning":
            logger.warning(message)
        elif level == "error":
            logger.error(message)

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
            logger.warning(f"帧头偏移量 {offset} 超出数据范围 {len(raw)}")
            return None, None, None, None, len(raw)
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        # 当帧体长度超过剩余捕获数据时，使用剩余长度
        frame_end = offset + 9 + frame_len
        if frame_end > len(raw):
            logger.warning(f"帧长度超过捕获长度, 原长度={frame_len}, 调整为剩余长度")
            frame_end = len(raw)
            frame_len = frame_end - (offset + 9)
            frame_header.length = frame_len
        frame_data = raw[offset + 9:frame_end]
        return frame_header, frame_len, frame_type, frame_data, frame_end
    except Exception as e:
        logger.error(f"帧解析错误: {str(e)}")
        return None, None, None, None, len(raw)

def modify_json_data(payload):
    """修改 JSON 数据中的目标字段，支持变量替换"""
    try:
        if not payload.strip():
            logger.debug("跳过空数据段")
            return None
        
        # 尝试解码为字符串
        try:
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8')
            else:
                payload_str = payload
        except UnicodeDecodeError:
            logger.warning("JSON数据解码失败，尝试以原始形式处理")
            payload_str = payload
            
        data = json.loads(payload_str)
        modified = False
        
        # 使用全局变量替换映射
        var_map = JSON_FIELD_MAP
        
        def recursive_modify(obj):
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in list(obj.items()):  # 使用list()创建键值对的副本
                    if key == "ismfId":
                        # 只替换最后一段
                        parts = value.rsplit("-", 1)
                        if len(parts) == 2:
                            new_val = f"{parts[0]}-{ismfId1}"
                            if value != new_val:
                                obj[key] = new_val
                                modified = True
                                logger.info(f"替换 ismfId: {value} -> {new_val}")
                    elif key == "ismfPduSessionUri":
                        # 替换host和最后数字
                        m = re.match(r"http://([\d.]+):\d+/(.+/)(\d+)", value)
                        if m:
                            new_val = f"http://{dip1}:80/{m.group(2)}{pduSessionId1}"
                            if value != new_val:
                                obj[key] = new_val
                                modified = True
                                logger.info(f"替换 ismfPduSessionUri: {value} -> {new_val}")
                    elif key in var_map and var_map[key] is not None:
                        if value != var_map[key]:
                            obj[key] = var_map[key]
                            modified = True
                            logger.info(f"替换 {key}: {value} -> {var_map[key]}")
                    elif key in ["icnTunnelInfo", "cnTunnelInfo"] and isinstance(value, dict):
                        for subk in ["ipv4Addr", "gtpTeid"]:
                            if subk in value and value.get(subk) != var_map[key][subk]:
                                old_val = value[subk]
                                value[subk] = var_map[key][subk]
                                modified = True
                                logger.info(f"替换 {key}.{subk}: {old_val} -> {var_map[key][subk]}")
                    elif isinstance(value, (dict, list)):
                        recursive_modify(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        recursive_modify(item)
        
        recursive_modify(data)
        if modified:
            logger.info("JSON数据已修改")
            return json.dumps(data, indent=None, separators=(',', ':')).encode()
        else:
            logger.debug("JSON数据无需修改")
            return None
    except Exception as e:
        logger.error(f"JSON处理错误: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def process_http2_data_frame(frame_data):
    """处理 HTTP/2 DATA 帧中的多部分数据"""
    if not frame_data:
        return frame_data
        
    if b"--++Boundary" in frame_data:
        # 多部分数据
        logger.debug("处理多部分数据")
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    # 按双 CRLF 分割获取 JSON 部分
                    segments = parts[i + 1].split(b"\r\n\r\n", 1)
                    if len(segments) == 2:
                        json_part = segments[1]
                        # 修改JSON字段
                        modified = modify_json_data(json_part)
                        if modified:
                            logger.info("更新多部分数据中的JSON部分")
                            parts[i + 1] = segments[0] + b"\r\n\r\n" + modified
        return b''.join(parts)
    else:
        # 尝试作为JSON处理
        try:
            modified = modify_json_data(frame_data)
            return modified if modified else frame_data
        except Exception:
            # 非JSON数据，直接返回原数据
            return frame_data

def raw_binary_search_replace(data, search_strings, replacement_string):
    """
    在原始二进制数据中查找并替换多个模式
    
    Args:
        data: 要处理的二进制数据
        search_strings: 要查找的模式列表(bytes)
        replacement_string: 替换内容(bytes)
    
    Returns:
        修改后的二进制数据
    """
    result = data
    for pattern in search_strings:
        result = result.replace(pattern, replacement_string)
    return result

def process_packet(pkt, seq_diff, ip_replacements, original_length=None, new_length=None):
    """
    处理数据包：IP替换和TCP序号/ACK修正
    """
    if pkt.haslayer(IP):
        if pkt[IP].src in ip_replacements:
            logger.info(f"替换源IP {pkt[IP].src} -> {ip_replacements[pkt[IP].src]}")
            pkt[IP].src = ip_replacements[pkt[IP].src]
        if pkt[IP].dst in ip_replacements:
            logger.info(f"替换目的IP {pkt[IP].dst} -> {ip_replacements[pkt[IP].dst]}")
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

def modify_header_field(headers, field_name, new_value, case_sensitive=False):
    """修改头字段，支持二进制和字符串类型"""
    modified = False
    new_headers = []
    
    for name, value in headers:
        name_str = name.decode() if isinstance(name, bytes) else name
        
        # 检查字段名是否匹配（区分大小写或不区分）
        if (case_sensitive and name_str == field_name) or \
           (not case_sensitive and name_str.lower() == field_name.lower()):
            # 确保类型匹配
            if isinstance(value, bytes) and not isinstance(new_value, bytes):
                new_val = new_value.encode()
            elif not isinstance(value, bytes) and isinstance(new_value, bytes):
                new_val = new_value.decode()
            else:
                new_val = new_value
                
            logger.info(f"修改HTTP2头: {name_str}, 原值: {value} -> 新值: {new_val}")
            new_headers.append((name, new_val))
            modified = True
        else:
            new_headers.append((name, value))
            
    return new_headers, modified

def replace_path_context_id(path_str, new_id):
    """将路径中的数字部分替换为新的ID"""
    # 手动替换而不是使用正则表达式，避免分组引用问题
    parts = path_str.split("/")
    for i in range(len(parts)):
        if parts[i].isdigit():
            parts[i] = new_id
            break
    return "/".join(parts)

def process_special_headers(frame_data, pkt_idx):
    """特殊处理HTTP2 Headers帧"""
    try:
        # 第9、11、13、15号报文使用二进制替换方法，因为它们的头部可能无法由标准hpack正确解析
        if pkt_idx in {9, 11, 13, 15}:
            logger.info(f"对第{pkt_idx}个报文使用二进制替换方法")
            
            # 二进制搜索替换辅助函数
            def binary_replace(data, search_pattern, replace_pattern):
                if search_pattern in data:
                    logger.debug(f"找到模式: {search_pattern}")
                    return data.replace(search_pattern, replace_pattern)
                return data  # 返回原数据，而不是None，这样可以链式调用
                  # 第11号报文特殊处理 - 替换authority和path
            if pkt_idx == 11:
                logger.info(f"特殊处理第{pkt_idx}号报文")
                # 尝试查找并替换authority - 增强匹配模式
                possible_patterns = [
                    b'200.20.20.25:8080', 
                    b'200.20.20.25',
                    bytes([0x32, 0x30, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x35]),  # "200.20.20.25" 的ASCII
                    b':authority: 200.20.20.25',
                    b':authority:200.20.20.25',
                    b':authority: 200.20.20.25:8080',
                    b':authority:200.20.20.25:8080'
                ]
                
                replacement = auth1.encode()
                
                # 强制直接替换authority - 先尝试完整替换
                temp_data = frame_data
                for i, pattern in enumerate(possible_patterns):
                    replaced_data = binary_replace(temp_data, pattern, replacement if i < 2 else pattern.replace(b'200.20.20.25', replacement))
                    if replaced_data != temp_data:
                        temp_data = replaced_data
                        logger.info(f"成功替换第{pkt_idx}号报文的authority模式{i}: {pattern} -> {replacement}")
                
                # 替换完成后记录日志
                if temp_data != frame_data:
                    logger.info(f"成功替换第{pkt_idx}号报文的authority为: {auth1}")
                frame_data = temp_data
                
                # 尝试替换path中的context_ID
                # 使用正确的字节模式
                path_pattern = re.compile(b'/nsmf-pdusession/v1/sm-contexts/(\\d+)')
                match = path_pattern.search(frame_data)
                if match:
                    old_context = match.group(1)
                    new_path = path_pattern.sub(f'/nsmf-pdusession/v1/sm-contexts/{context_ID}'.encode(), frame_data)
                    logger.info(f"成功替换第{pkt_idx}号报文中的context_ID: {old_context.decode()} -> {context_ID}")
                    frame_data = new_path
                
                # 直接在原始二进制数据中查找并替换:authority字段 - 更精确定位
                auth_pos = frame_data.find(b':authority')
                if auth_pos > 0:
                    # 查找值的开始位置
                    val_start = frame_data.find(b':', auth_pos + 10)
                    if val_start > 0:
                        # 查找值的结束位置 - 更多可能的分隔符
                        end_markers = [b'\r\n', b';', b'\x00', b'\n']
                        val_end = -1
                        for marker in end_markers:
                            pos = frame_data.find(marker, val_start)
                            if pos > 0 and (val_end == -1 or pos < val_end):
                                val_end = pos
                        
                        # 如果仍未找到结束位置，尝试下一个字段
                        if val_end < 0:
                            # 查找下一个HTTP/2头字段
                            next_field_pos = -1
                            for prefix in [b':', b'content-', b'user-', b'accept-', b'cache-']:
                                pos = frame_data.find(prefix, val_start + 1)
                                if pos > 0 and (next_field_pos == -1 or pos < next_field_pos):
                                    next_field_pos = pos
                            
                            if next_field_pos > 0:
                                val_end = next_field_pos
                            else:
                                # 没有找到明确的结束，使用固定长度
                                val_end = val_start + 20  # 假设值不会超过20个字符
                        
                        # 替换值
                        new_frame_data = frame_data[:val_start+1] + b' ' + auth1.encode() + frame_data[val_end:]
                        frame_data = new_frame_data
                        logger.info(f"直接二进制替换第{pkt_idx}号报文的:authority值为: {auth1}")
                
                # 额外保障: 无论如何都确保authority被正确设置
                if b':authority: ' + auth1.encode() not in frame_data and b':authority:' + auth1.encode() not in frame_data:
                    logger.info(f"使用额外的强制替换方法确保authority字段正确")
                    # 再次尝试常见编码模式
                    for auth_pattern in [b':authority: ', b':authority:']:
                        pos = frame_data.find(auth_pattern)
                        if pos >= 0:
                            val_start = pos + len(auth_pattern)
                            val_end = val_start
                            # 找到值的结束位置
                            while val_end < len(frame_data) and not (frame_data[val_end:val_end+1] in [b'\r', b'\n', b';', b':']):
                                val_end += 1
                            
                            # 直接替换整个值
                            frame_data = frame_data[:val_start] + auth1.encode() + frame_data[val_end:]
                            logger.info(f"二次强制替换authority值: {auth1}")
                            break
                
                return frame_data
                  # 第13号报文特殊处理 - 替换authority
            elif pkt_idx == 13:
                # 尝试查找并替换"authority: 200.20.20.25:8080" - 增强匹配模式
                possible_patterns = [
                    b'200.20.20.25:8080', 
                    b'200.20.20.25',
                    bytes([0x32, 0x30, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x35]),  # "200.20.20.25" 的ASCII
                    b':authority: 200.20.20.25',
                    b':authority:200.20.20.25',
                    b':authority: 200.20.20.25:8080',
                    b':authority:200.20.20.25:8080'
                ]
                
                replacement = auth1.encode()
                
                # 强制直接替换authority - 多种模式尝试
                temp_data = frame_data
                for i, pattern in enumerate(possible_patterns):
                    replaced_data = binary_replace(temp_data, pattern, replacement if i < 2 else pattern.replace(b'200.20.20.25', replacement))
                    if replaced_data != temp_data:
                        temp_data = replaced_data
                        logger.info(f"成功替换第{pkt_idx}号报文的authority模式{i}: {pattern} -> {replacement}")
                
                # 替换完成后记录日志
                if temp_data != frame_data:
                    logger.info(f"成功替换第{pkt_idx}号报文的authority为: {auth1}")
                frame_data = temp_data
                
                # 检查是否包含:authority字段 - 更精确的检测
                has_authority = False
                for auth_marker in [b':authority:', b':authority: ']:
                    if auth_marker in frame_data:
                        has_authority = True
                        # 尝试直接替换值部分
                        pos = frame_data.find(auth_marker)
                        if pos >= 0:
                            val_start = pos + len(auth_marker)
                            val_end = val_start
                            # 找到值的结束位置
                            while val_end < len(frame_data) and not (frame_data[val_end:val_end+1] in [b'\r', b'\n', b';', b':', b' ']):
                                val_end += 1
                            
                            # 确保找到的值区间有效
                            if val_end > val_start:
                                # 替换authority值
                                curr_value = frame_data[val_start:val_end]
                                if curr_value != auth1.encode():
                                    frame_data = frame_data[:val_start] + auth1.encode() + frame_data[val_end:]
                                    logger.info(f"精确替换第{pkt_idx}号报文authority值: {curr_value} -> {auth1}")
                
                # 如果没有找到:authority字段，添加一个
                if not has_authority:
                    # 尝试在合适的位置插入authority字段
                    # 通常在:method和:path头部之后
                    path_pos = frame_data.find(b':path')
                    if path_pos > 0:
                        insert_pos = path_pos
                        authority_field = b':authority'
                        authority_value = auth1.encode()
                        # 根据现有头部格式确定分隔符
                        if b': ' in frame_data:
                            authority_header = authority_field + b': ' + authority_value + b'\r\n'
                        else:
                            authority_header = authority_field + b':' + authority_value + b'\r\n'
                        
                        new_frame_data = frame_data[:insert_pos] + authority_header + frame_data[insert_pos:]
                        logger.info(f"在第{pkt_idx}号报文中添加缺失的authority字段: {auth1}")
                        frame_data = new_frame_data
                  # 额外检查：再次扫描frame_data确保authority正确设置
                if b':authority: ' + auth1.encode() not in frame_data and b':authority:' + auth1.encode() not in frame_data:
                    logger.warning(f"第{pkt_idx}个报文未能确认authority字段设置成功，尝试额外替换方法")
                    
                    # 查找任何包含authority的位置
                    auth_pos = frame_data.find(b':authority')
                    if auth_pos >= 0:
                        # 找到值的部分
                        val_start = frame_data.find(b':', auth_pos + 10)
                        if val_start > 0:
                            # 明确查找值的结束位置
                            end_markers = [b'\r\n', b';', b'\x00', b'\n']
                            val_end = -1
                            for marker in end_markers:
                                pos = frame_data.find(marker, val_start)
                                if pos > 0 and (val_end == -1 or pos < val_end):
                                    val_end = pos
                            
                            if val_end < 0:
                                # 如果找不到明确的结束，使用下一个冒号位置
                                val_end = frame_data.find(b':', val_start + 1)
                                if val_end < 0:
                                    val_end = val_start + 20  # 安全限制
                            
                            # 强制替换值
                            frame_data = frame_data[:val_start+1] + b' ' + auth1.encode() + frame_data[val_end:]
                            logger.info(f"强制二进制替换第{pkt_idx}号报文的:authority值为: {auth1}")
                    else:
                        # 如果完全找不到:authority字段，则强制添加
                        # 查找method或path字段作为插入点
                        for insert_marker in [b':method', b':path', b':scheme']:
                            insert_pos = frame_data.find(insert_marker)
                            if insert_pos > 0:
                                # 找到合适的插入点
                                authority_header = b':authority: ' + auth1.encode() + b'\r\n'
                                frame_data = frame_data[:insert_pos] + authority_header + frame_data[insert_pos:]
                                logger.info(f"强制添加第{pkt_idx}号报文的:authority字段: {auth1}")
                                break
                
                # 极端情况：如果之前的所有方法都失败，直接强制创建一个头部块
                if b':authority' not in frame_data:
                    logger.warning(f"所有方法都未能添加authority字段，使用全新头部块")
                    # 构建一个基本的HTTP/2头部块
                    basic_headers = [
                        (b':method', b'POST'),
                        (b':scheme', b'http'),
                        (b':authority', auth1.encode()),
                        (b':path', b'/nsmf-pdusession/v1/pdu-sessions')
                    ]
                    encoder = Encoder()
                    new_headers_data = encoder.encode(basic_headers)
                    if b':' in frame_data:  # 如果原有头部还有某些部分可用
                        # 尝试保留其他头部字段
                        start_pos = 0
                        while start_pos < len(frame_data):
                            field_pos = frame_data.find(b':', start_pos)
                            if field_pos < 0:
                                break
                            # 查找字段名结束位置
                            value_pos = frame_data.find(b':', field_pos + 1)
                            if value_pos < 0:
                                break
                            # 查找值结束位置
                            end_pos = -1
                            for marker in [b'\r\n', b'\n', b';']:
                                pos = frame_data.find(marker, value_pos)
                                if pos > 0 and (end_pos < 0 or pos < end_pos):
                                    end_pos = pos
                            if end_pos < 0:
                                end_pos = frame_data.find(b':', value_pos + 1)
                                if end_pos < 0:
                                    break
                            # 提取字段和值
                            field_name = frame_data[field_pos:value_pos].strip()
                            field_value = frame_data[value_pos+1:end_pos].strip()
                            if field_name not in [b':method', b':scheme', b':authority', b':path']:
                                logger.info(f"保留原有头部字段: {field_name}: {field_value}")
                                frame_data = frame_data[:field_pos] + frame_data[end_pos:]
                            start_pos = end_pos + 1
                    
                    # 合并新头部和原有数据
                    frame_data = new_headers_data + frame_data
                    logger.info(f"为第{pkt_idx}号报文创建了全新的头部块，包含authority: {auth1}")
                
                return frame_data            # 第15号报文特殊处理 - 替换location
            elif pkt_idx == 15:
                # 尝试找到location字段 - 更全面的匹配模式
                possible_patterns = [
                    b'location:', 
                    b'Location:',
                    b'location :', 
                    b'Location :',
                ]
                
                # 构建新的location值 - 注意：使用auth1而不是sip1确保与:authority一致
                new_location = f"http://{auth1}:80/nsmf-pdusession/v1/pdu-sessions/{context_ID}"
                new_location_bytes = new_location.encode()
                
                # 优先处理：直接查找并替换HTTP URI
                uri_pattern = re.compile(br'http://[0-9.]+(?::[0-9]+)?/nsmf-pdusession/v1/pdu-sessions/[0-9]+')
                match = uri_pattern.search(frame_data)
                if match:
                    old_uri = match.group(0)
                    logger.info(f"找到完整URL: {old_uri}")
                    frame_data = frame_data.replace(old_uri, new_location_bytes)
                    logger.info(f"直接替换URL: {old_uri} -> {new_location_bytes}")
                    location_found = True
                else:
                    # 如果找不到完整URL，尝试定位location头部
                    location_found = False
                    for pattern in possible_patterns:
                        loc_pos = frame_data.find(pattern)
                        if loc_pos >= 0:
                            logger.info(f"找到location字段位置: {loc_pos}")
                            location_found = True
                            # 尝试查找URI部分并替换
                            value_start = loc_pos + len(pattern)
                            
                            # 找到原始URI的结束位置 - 更全面的边界检测
                            end_markers = [b'\r\n', b';', b'\x00', b'\n', b':']
                            next_header = -1
                            for marker in end_markers:
                                pos = frame_data.find(marker, value_start)
                                if pos > 0 and (next_header == -1 or pos < next_header):
                                    next_header = pos
                            
                            if next_header < 0:
                                next_header = len(frame_data)
                            
                            # 获取当前URI值
                            current_uri = frame_data[value_start:next_header].strip()
                            if current_uri:
                                logger.info(f"当前location URI: {current_uri}")
                            
                            # 替换整个URI，确保使用新值
                            new_frame_data = frame_data[:value_start] + b' ' + new_location_bytes + frame_data[next_header:]
                            logger.info(f"替换location URI为: {new_location}")
                            frame_data = new_frame_data
                            break
                
                # 直接尝试替换整个location头字段及其值
                if not location_found:
                    # 可能的完整location头格式
                    complete_patterns = [
                        b'location: http://', 
                        b'Location: http://',
                        b'location:http://', 
                        b'Location:http://'
                    ]
                    
                    for pattern in complete_patterns:
                        loc_pos = frame_data.find(pattern)
                        if loc_pos >= 0:
                            logger.info(f"找到完整location头部开始位置: {loc_pos}")
                            # 找uri的结束位置
                            uri_end = -1
                            for end_marker in [b'\r\n', b';', b'\n']:
                                pos = frame_data.find(end_marker, loc_pos + len(pattern))
                                if pos > 0 and (uri_end == -1 or pos < uri_end):
                                    uri_end = pos
                            
                            if uri_end < 0:
                                uri_end = len(frame_data)
                            
                            # 替换整个location header + value
                            header_prefix = pattern[:pattern.find(b'http://')]
                            new_frame_data = frame_data[:loc_pos] + header_prefix + new_location_bytes + frame_data[uri_end:]
                            logger.info(f"替换整个location头部及值为: {header_prefix + new_location_bytes}")
                            frame_data = new_frame_data
                            location_found = True
                            break
                
                # 使用更激进的方式：直接搜索并替换常见URL模式
                if not location_found:
                    # 尝试匹配完整的URL模式
                    url_pattern = re.compile(b'(http://[0-9.]+(?::[0-9]+)?/nsmf-pdusession/v1/pdu-sessions/[0-9]+)')
                    match = url_pattern.search(frame_data)
                    if match:
                        old_url = match.group(0)
                        logger.info(f"找到完整URL模式: {old_url}")
                        frame_data = frame_data.replace(old_url, new_location_bytes)
                        logger.info(f"替换URL: {old_url} -> {new_location_bytes}")
                        location_found = True
                
                # 最后尝试：使用更激进的方式直接替换IP和端口
                patterns_to_replace = [
                    b'200.20.20.25:8080',
                    b'200.20.20.25', 
                    bytes([0x32, 0x30, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x35])
                ]
                
                # 应用所有替换
                temp_data = frame_data
                for pattern in patterns_to_replace:
                    temp_data = binary_replace(temp_data, pattern, sip1.encode())
                
                if temp_data != frame_data:
                    logger.info(f"通过二进制IP替换修改了第{pkt_idx}个报文中的URI")
                    frame_data = temp_data
                    location_found = True
                
                # 替换session ID
                session_pattern = re.compile(b'/pdu-sessions/([0-9]+)')
                match = session_pattern.search(frame_data)
                if match:
                    old_id = match.group(1)
                    if old_id != context_ID.encode():
                        new_path = session_pattern.sub(f'/pdu-sessions/{context_ID}'.encode(), frame_data)
                        logger.info(f"替换session ID: {old_id} -> {context_ID}")
                        frame_data = new_path
                
                if not location_found:
                    logger.warning(f"第{pkt_idx}个报文未能修改location字段")
                
                return frame_data
        
        # 对于其他报文使用标准hpack解析方法
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        modified = False
        new_headers = []
        
        # 检查是否有authority字段存在
        has_authority = False
        for name, value in headers:
            name_str = name.decode() if isinstance(name, bytes) else name
            if name_str == ":authority":
                has_authority = True
                break
                    
        # 显示原始头部信息
        logger.debug(f"包{pkt_idx} HEADERS原始内容:")
        for i, (name, value) in enumerate(headers):
            name_str = name.decode() if isinstance(name, bytes) else name
            value_str = value.decode() if isinstance(value, bytes) and not isinstance(value, str) else value
            logger.debug(f"  [{i}] {name_str}: {value_str}")
        
        # 第9、11和13包的特殊处理：修改:authority和:path
        if pkt_idx in {9, 11, 13}:
            for name, value in headers:
                name_str = name.decode() if isinstance(name, bytes) else name
                # 处理:authority字段
                if name_str == ":authority":
                    if value != auth1:
                        new_val = auth1
                        if isinstance(value, bytes):
                            new_val = auth1.encode()
                        new_headers.append((name, new_val))
                        logger.info(f"替换:authority: {value} -> {new_val}")
                        modified = True
                    else:
                        new_headers.append((name, value))
                
                # 处理:path字段
                elif name_str == ":path":
                    value_str = value.decode() if isinstance(value, bytes) else value
                    new_path = replace_path_context_id(value_str, context_ID)
                    if new_path != value_str:
                        if isinstance(value, bytes):
                            new_headers.append((name, new_path.encode()))
                        else:
                            new_headers.append((name, new_path))
                        logger.info(f"替换:path: {value_str} -> {new_path}")
                        modified = True
                    else:
                        new_headers.append((name, value))
                else:
                    new_headers.append((name, value))
        
        # 第15包的特殊处理：修改location字段
        elif pkt_idx == 15:
            for name, value in headers:
                name_str = name.decode() if isinstance(name, bytes) else name
                
                # 处理location字段
                if name_str.lower() == "location" if isinstance(name_str, str) else False:
                    value_str = value.decode() if isinstance(value, bytes) else value
                    # 对于字符串类型的值使用正则表达式匹配
                    if isinstance(value_str, str):
                        url_match = re.match(r"(http://)[\d\.]+:\d+(.*)", value_str)
                        if url_match:
                            new_loc = f"{url_match.group(1)}{sip1}:80{url_match.group(2)}"
                            if new_loc != value_str:
                                if isinstance(value, bytes):
                                    new_headers.append((name, new_loc.encode()))
                                else:
                                    new_headers.append((name, new_loc))
                                logger.info(f"替换location: {value_str} -> {new_loc}")
                                modified = True
                                continue
                    # 如果没有匹配或者值不是字符串类型，保留原始值
                    new_headers.append((name, value))
                else:
                    new_headers.append((name, value))
        
        # 检查是否需要添加缺失的authority字段（针对第11和13号报文）
        if pkt_idx in {11, 13} and not has_authority:
            # 添加缺失的authority字段
            authority_field = ":authority"
            if any(isinstance(name, bytes) for name, _ in headers):
                authority_field = b":authority"
            authority_value = auth1
            if any(isinstance(value, bytes) for _, value in headers):
                authority_value = auth1.encode()
            new_headers.append((authority_field, authority_value))
            logger.info(f"添加缺失的:authority字段: {authority_value}")
            modified = True
            
        # 编码修改后的头并返回
        if modified:
            logger.debug(f"包{pkt_idx} HEADERS修改后:")
            for i, (name, value) in enumerate(new_headers):
                name_str = name.decode() if isinstance(name, bytes) else name
                value_str = value.decode() if isinstance(value, bytes) and not isinstance(value, str) else value
                logger.debug(f"  [{i}] {name_str}: {value_str}")
            
            encoder = Encoder()
            new_data = encoder.encode(new_headers)
            logger.info(f"HEADERS已修改，新长度: {len(new_data)}")
            return new_data
        
        return frame_data
    
    except Exception as e:
        logger.error(f"处理Headers错误: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return frame_data

def update_content_length(headers_data, body_length):
    """更新HEADERS中的Content-Length字段"""
    try:
        # 先尝试直接在二进制数据中替换content-length值
        content_length_binary_updated = False
        
        # 尝试查找content-length字段
        for cl_pattern in [b'content-length:', b'content-length: ', b'Content-Length:', b'Content-Length: ']:
            cl_pos = headers_data.find(cl_pattern)
            if cl_pos >= 0:
                # 找到了content-length字段
                val_start = cl_pos + len(cl_pattern)
                val_end = val_start
                # 找到值的结束位置
                for end_marker in [b'\r\n', b'\n', b';']:
                    pos = headers_data.find(end_marker, val_start)
                    if pos > 0:
                        val_end = pos
                        break
                
                if val_end > val_start:
                    # 提取当前值并替换
                    current_value = headers_data[val_start:val_end].strip()
                    try:
                        current_len = int(current_value)
                        if current_len != body_length:
                            # 替换值
                            headers_data = headers_data[:val_start] + str(body_length).encode() + headers_data[val_end:]
                            logger.info(f"直接替换Content-Length: {current_len} -> {body_length}")
                            content_length_binary_updated = True
                    except ValueError:
                        logger.warning(f"无法解析Content-Length值: {current_value}")
        
        # 如果直接二进制替换成功，返回结果
        if content_length_binary_updated:
            return headers_data
        
        # 否则，使用HPACK解码/编码方式处理
        try:
            decoder = Decoder()
            headers = decoder.decode(headers_data)
            modified = False
            new_headers = []
            content_length_found = False
            
            for name, value in headers:
                name_str = name.decode() if isinstance(name, bytes) else name
                # 检查内容类型安全地处理
                is_content_length = (isinstance(name_str, str) and name_str.lower() == "content-length")
                
                if is_content_length:
                    content_length_found = True
                    # 确认类型一致性
                    if isinstance(value, bytes):
                        new_headers.append((name, str(body_length).encode()))
                    else:
                        new_headers.append((name, str(body_length)))
                    logger.info(f"更新Content-Length: {value} -> {body_length}")
                    modified = True
                else:
                    new_headers.append((name, value))
            
            # 如果没有找到content-length字段，添加一个
            if not content_length_found:
                # 确定应该使用什么类型的键和值
                content_length_key = "content-length"
                content_length_value = str(body_length)
                
                # 检查headers中是否有bytes类型的键
                if any(isinstance(name, bytes) for name, _ in headers):
                    content_length_key = b"content-length"
                
                # 检查headers中是否有bytes类型的值
                if any(isinstance(value, bytes) for _, value in headers):
                    content_length_value = str(body_length).encode()
                    
                new_headers.append((content_length_key, content_length_value))
                logger.info(f"添加Content-Length: {body_length}")
                modified = True
            
            if modified:
                encoder = Encoder()
                return encoder.encode(new_headers)
            return headers_data
        except Exception as e:
            logger.error(f"HPACK处理Content-Length错误: {e}")
            
            # 如果解码失败，尝试强制添加content-length字段
            if b'content-length' not in headers_data.lower() and b'Content-Length' not in headers_data:
                # 寻找插入点 - 通常在其他头部字段之后
                insert_pos = -1
                for marker in [b'\r\n\r\n', b'\n\n', b'\r\n', b'\n']:
                    pos = headers_data.rfind(marker)
                    if pos > 0:
                        insert_pos = pos
                        break
                
                if insert_pos > 0:
                    # 直接在末尾添加content-length字段
                    cl_header = b'\r\ncontent-length: ' + str(body_length).encode() 
                    headers_data = headers_data[:insert_pos] + cl_header + headers_data[insert_pos:]
                    logger.info(f"强制添加Content-Length: {body_length}")
                    return headers_data
            
            return headers_data
        
    except Exception as e:
        logger.error(f"更新Content-Length错误: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return headers_data

def extract_frames(raw_data):
    """提取HTTP/2帧并返回帧列表"""
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
    """
    对整个报文应用直接的二进制替换(用于极端情况)
    增强版 - 更全面的替换模式和更智能的处理
    """
    if not pkt.haslayer(Raw):
        return False
    
    modified = False
    load = bytes(pkt[Raw].load)
    
    # 全局IP和端口替换模式
    ip_replacements = [
        # 常规文本形式
        (b'200.20.20.25:8080', f"{auth1}:80".encode()),
        (b'200.20.20.25', auth1.encode()),
        # ASCII编码形式
        (bytes([0x32, 0x30, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32, 0x35]), auth1.encode()),
    ]
    
    # 针对特定报文的header字段替换
    if idx in {9, 11, 13}:
        # authority头部替换
        authority_replacements = []
        
        # 所有可能的authority表示方式
        auth_patterns = [
            b':authority:', b':authority: ',
            b'authority:', b'authority: '
        ]
        
        # 查找所有authority字段位置
        for pattern in auth_patterns:
            pos = load.find(pattern)
            if pos >= 0:
                # 找到值的开始和结束位置
                val_start = pos + len(pattern)
                val_end = val_start
                
                # 寻找值的结束边界
                for end_char in [b'\r', b'\n', b';', b':', b' ']:
                    next_pos = load.find(end_char, val_start)
                    if next_pos > 0:
                        if val_end == val_start or next_pos < val_end:
                            val_end = next_pos
                
                if val_end == val_start:
                    # 安全限制
                    val_end = min(val_start + 30, len(load))
                
                # 提取当前值并构建替换模式
                current_val = load[val_start:val_end]
                if current_val and current_val != auth1.encode():
                    # 构建完整pattern和replacement
                    full_pattern = pattern + current_val
                    full_replacement = pattern + auth1.encode()
                    authority_replacements.append((full_pattern, full_replacement))
        
        # 添加到替换列表
        ip_replacements.extend(authority_replacements)
    
    # 对第15号报文的特殊处理 - 替换location URI
    if idx == 15:
        # 全面查找location URI的模式
        location_patterns = []
        
        # 1. 查找完整的location头和URI
        loc_headers = [b'location:', b'Location:', b'location :', b'Location :']
        for header in loc_headers:
            pos = load.find(header)
            if pos >= 0:
                val_start = pos + len(header)
                # 找到URI结束位置
                val_end = -1
                for end_mark in [b'\r\n', b'\n', b';', b':']:
                    next_pos = load.find(end_mark, val_start)
                    if next_pos > 0 and (val_end < 0 or next_pos < val_end):
                        val_end = next_pos
                
                if val_end < 0:
                    val_end = len(load)
                
                uri_val = load[val_start:val_end].strip()
                if uri_val and b'http://' in uri_val:
                    # 构建完整替换
                    new_uri = f"http://{sip1}:80/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()
                    location_patterns.append((header + b' ' + uri_val, header + b' ' + new_uri))
        
        # 2. 直接查找完整URL
        url_patterns = [
            # 完整URL格式
            rb'http://[\d\.]+(?::\d+)?/nsmf-pdusession/v1/pdu-sessions/\d+',
            # 部分URL格式
            rb'/nsmf-pdusession/v1/pdu-sessions/\d+'
        ]
        
        for pattern_str in url_patterns:
            pattern = re.compile(pattern_str)
            for match in pattern.finditer(load):
                old_url = match.group(0)
                if b'/pdu-sessions/' in old_url:
                    if b'http://' in old_url:
                        new_url = f"http://{sip1}:80/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()
                    else:
                        new_url = f"/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()
                    location_patterns.append((old_url, new_url))
        
        # 添加到替换列表
        ip_replacements.extend(location_patterns)
    
    # 先应用所有IP替换
    for pattern, replacement in ip_replacements:
        if pattern in load:
            new_load = load.replace(pattern, replacement)
            if new_load != load:
                modified = True
                load = new_load
                logger.info(f"对第{idx}号报文直接替换: {pattern} -> {replacement}")
      # 针对路径中的context_ID单独处理
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
                logger.info(f"替换context_ID: {old_id} -> {context_ID}")
      # 第15号报文中的session ID单独处理
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
                    logger.info(f"替换session_ID: {old_id} -> {context_ID}")
    
    # 如果有修改，更新报文负载
    if modified:
        pkt[Raw].load = load
        logger.info(f"对第{idx}号报文进行了直接的二进制替换")
    
    return modified

def main():
    """主处理流程"""
    PCAP_IN = "pcap/N16_create_16p.pcap"
    PCAP_OUT = "pcap/N16_1413.pcap"
    
    logger.info(f"开始处理文件 {PCAP_IN}")
    if not os.path.exists(PCAP_IN):
        logger.error(f"输入文件不存在: {PCAP_IN}")
        return
        
    packets = rdpcap(PCAP_IN)
    modified_packets = []
    
    seq_diff = {}
    
    # 记录需要特殊处理的报文序号（从1开始）
    target_pkts = {9, 11, 13, 15}
    
    for idx, pkt in enumerate(packets, 1):
        modified = False
        original_length = None
        new_length = None
        
        logger.debug(f"处理第{idx}个报文")        # 处理目标报文
        if idx in target_pkts and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            logger.info(f"特殊处理第{idx}个报文")
            
            # 先尝试直接在原始负载上进行二进制替换（第一阶段）
            direct_modified = apply_direct_binary_replacements(pkt, idx)
            
            # 获取可能已修改的原始负载
            raw = bytes(pkt[Raw].load)
            
            # 提取所有帧
            frames = extract_frames(raw)
            if not frames:
                logger.warning(f"第{idx}个报文未找到有效HTTP/2帧")
                continue
                
            # 初始化新负载
            new_payload = b''
            content_length_frames = []  # 存储含content-length的帧
            data_frames = []  # 存储DATA帧            # 第一轮：处理headers帧
            for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                if frame_type == 0x1:  # HEADERS帧
                    # 特殊处理headers
                    if idx in {9, 11, 13, 15}:  # 处理所有目标报文的HEADERS帧
                        logger.info(f"处理第{idx}个报文的第{frame_idx}个HEADERS帧")
                        new_header_data = process_special_headers(frame_data, idx)
                        if new_header_data != frame_data:
                            modified = True
                            # 更新帧长度
                            frame_header.length = len(new_header_data)
                            # 更新帧内容
                            frames[frame_idx] = (frame_header, frame_type, new_header_data, start_offset, start_offset + 9 + len(new_header_data))
                      
                    # 检查是否包含content-length字段
                    try:
                        # 直接二进制方式检查content-length字段
                        if b'content-length' in frame_data.lower() or b'Content-Length' in frame_data:
                            content_length_frames.append(frame_idx)
                            logger.debug(f"在第{idx}个报文的第{frame_idx}个帧中找到content-length字段")
                        else:
                            # 如果没有找到，尝试使用HPACK解码检查
                            try:
                                decoder = Decoder()
                                headers = decoder.decode(frame_data)
                                for name, _ in headers:
                                    name_str = name.decode() if isinstance(name, bytes) else name
                                    # 安全处理字符串类型
                                    is_content_length = isinstance(name_str, str) and name_str.lower() == "content-length"
                                    if is_content_length:
                                        content_length_frames.append(frame_idx)
                                        logger.debug(f"通过HPACK解码在第{idx}个报文的第{frame_idx}个帧中找到content-length字段")
                                        break
                            except Exception as e:
                                logger.error(f"解析HEADERS错误: {e}")
                    except Exception as e:
                        logger.error(f"检查content-length字段错误: {e}")
                
                elif frame_type == 0x0:  # DATA帧
                    data_frames.append(frame_idx)
            
            # 第二轮：处理DATA帧和content-length
            for data_idx in data_frames:
                frame_header, frame_type, frame_data, start_offset, end_offset = frames[data_idx]
                
                # 修改DATA帧内容
                logger.debug(f"处理第{idx}个报文的DATA帧，原始长度: {len(frame_data)}")
                new_data = process_http2_data_frame(frame_data)
                if new_data is not None and new_data != frame_data:
                    modified = True
                    new_data_len = len(new_data)
                    logger.info(f"第{idx}个报文DATA帧已修改，新长度: {new_data_len}")
                    
                    # 更新帧长度
                    frame_header.length = new_data_len
                    # 更新帧内容
                    frames[data_idx] = (frame_header, frame_type, new_data, start_offset, start_offset + 9 + new_data_len)
                    
                    # 更新相关的content-length
                    if content_length_frames:
                        for cl_idx in content_length_frames:
                            cl_frame_header, cl_frame_type, cl_frame_data, cl_start_offset, cl_end_offset = frames[cl_idx]
                            logger.debug(f"更新第{idx}个报文的content-length字段为: {new_data_len}")
                            new_cl_data = update_content_length(cl_frame_data, new_data_len)
                            if new_cl_data != cl_frame_data:
                                logger.info(f"第{idx}个报文的content-length已更新")
                                cl_frame_header.length = len(new_cl_data)
                                frames[cl_idx] = (cl_frame_header, cl_frame_type, new_cl_data, cl_start_offset, cl_start_offset + 9 + len(new_cl_data))
                    else:
                        # 如果找不到content-length字段，尝试在所有HEADERS帧中添加
                        for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                            if frame_type == 0x1:  # HEADERS帧
                                logger.info(f"在第{idx}个报文的HEADERS帧中添加缺失的content-length字段")
                                new_cl_data = update_content_length(frame_data, new_data_len)
                                if new_cl_data != frame_data:
                                    cl_frame_header = frame_header
                                    cl_frame_header.length = len(new_cl_data)
                                    frames[frame_idx] = (cl_frame_header, frame_type, new_cl_data, start_offset, start_offset + 9 + len(new_cl_data))
                                    logger.info(f"已在第{idx}个报文中添加content-length: {new_data_len}")
                                    modified = True
                                    break
              # 重建payload
            for frame_header, _, frame_data, _, _ in frames:
                new_payload += frame_header.build() + frame_data
            
            # 更新报文
            if modified:
                logger.info(f"第{idx}个报文已通过帧处理修改")
                original_length = len(raw)
                new_length = len(new_payload)
                pkt[Raw].load = new_payload
                
                # 在帧处理完成后再次应用直接二进制替换（第二阶段）- 保障修改成功
                second_direct_modified = apply_direct_binary_replacements(pkt, idx)
                if second_direct_modified:
                    logger.info(f"第{idx}个报文在帧处理后又通过二进制替换进一步修改")
                    # 更新长度差异
                    new_length = len(pkt[Raw].load)
        
        # 处理所有报文的IP和序列号
        process_packet(pkt, seq_diff, IP_REPLACEMENTS, original_length, new_length)
        modified_packets.append(pkt)
    
    logger.info(f"保存修改后的PCAP到 {PCAP_OUT}")
    wrpcap(PCAP_OUT, modified_packets)
    logger.info(f"处理完成，共处理 {len(packets)} 个报文")

if __name__ == "__main__":
    main()
