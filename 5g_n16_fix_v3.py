from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("5g_n16_fix_v3.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
            logger.warning(f"帧长度超过捕获长度，调整为剩余数据长度")
            frame_end = len(raw)
            frame_len = frame_end - (offset + 9)
            frame_header.length = frame_len
        frame_data = raw[offset + 9:frame_end]
        return frame_header, frame_len, frame_type, frame_data, frame_end
    except Exception as e:
        logger.error(f"帧解析错误: {str(e)}")
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
            logger.info("[跳过空数据段]")
            return None
            
        data = json.loads(payload_str)
        modified = False

        def recursive_modify(obj, modifications):
            """递归修改嵌套 JSON 对象"""
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in list(obj.items()):  # 使用list()创建副本，避免在迭代时修改
                    if key in modifications:
                        logger.info(f"修改 JSON 字段 {key}: {value} -> {modifications[key]}")
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
        logger.error(f"JSON处理错误: {str(e)}")
        return None

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
            logger.error(f"JSON解析错误: {str(e)}")
            modified_data = frame_data
            json_length = len(frame_data)

    return modified_data, json_length

def get_http2_headers(frame_data):
    """从HEADERS帧数据中解析HTTP/2头部"""
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        result = {}
        for name, value in headers:
            if isinstance(name, bytes):
                name = name.decode('utf-8', errors='ignore')
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='ignore')
            result[name.lower()] = value
        return result
    except Exception as e:
        logger.error(f"头部解析错误: {str(e)}")
        return {}

def set_headers_content_length(frame_data, content_length):
    """设置HEADERS帧中的content-length，确保只有一个content-length字段"""
    try:
        decoder = Decoder()
        encoder = Encoder()
        headers = decoder.decode(frame_data)
        new_headers = []
        content_length_found = False
        
        # 先收集所有非content-length的头部
        for name, value in headers:
            if isinstance(name, bytes):
                name = name.decode('utf-8', errors='ignore')
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='ignore')
            
            if name.lower() == 'content-length':
                if not content_length_found:
                    content_length_found = True
                    logger.info(f"设置 content-length: {value} -> {content_length}")
                    new_headers.append((name, str(content_length)))
            else:
                new_headers.append((name, value))
        
        # 如果没有找到content-length，添加一个
        if not content_length_found and content_length > 0:
            logger.info(f"添加 content-length: {content_length}")
            new_headers.append(('content-length', str(content_length)))
        
        return encoder.encode(new_headers)
    except Exception as e:
        logger.error(f"设置content-length失败: {str(e)}")
        return frame_data

def process_http2_headers_frame(frame_data, context_num):
    """处理 HTTP/2 HEADERS 帧，修改 path 和 authority 字段"""
    try:
        decoder = Decoder()
        encoder = Encoder()
        
        try:
            headers = decoder.decode(frame_data)
        except Exception as e:
            logger.error(f"HPACK解码错误: {str(e)}")
            return frame_data
            
        modified = False
        new_headers = []

        # 处理所有头部，不涉及content-length
        for name, value in headers:
            # 确保name和value都是字符串
            if isinstance(name, bytes):
                name = name.decode('utf-8', errors='ignore')
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='ignore')
                
            if name == ":path" and "sm-contexts" in value and "retrieve" in value:
                new_path = f"/nsmf-pdusession/v1/sm-contexts/{context_num}/retrieve"
                logger.info(f"修改 header {name}: {value} -> {new_path}")
                new_headers.append((name, new_path))
                modified = True
            elif name == ":authority":
                new_authority = "smf.smf"
                logger.info(f"修改 header {name}: {value} -> {new_authority}")
                new_headers.append((name, new_authority))
                modified = True
            else:
                new_headers.append((name, value))

        # 返回修改后的头部
        if modified:
            try:
                return encoder.encode(new_headers)
            except Exception as e:
                logger.error(f"HPACK编码错误: {str(e)}")
                return frame_data
        return frame_data
    except Exception as e:
        logger.error(f"Header处理错误: {str(e)}")
        return frame_data

def process_specific_packet(raw, context_num, modifications):
    """
    专门处理特定HTTP/2报文，确保content-length与DATA帧长度匹配
    适用于第11、13、15号报文等带有content-length的报文
    """
    try:
        # 提取所有帧
        frames = []
        offset = 0
        while offset + 9 <= len(raw):
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if frame_header is None:
                break
                
            frames.append({
                'offset': offset,
                'type': frame_type,
                'length': frame_len,
                'data': frame_data,
                'header': frame_header,
                'end': frame_end
            })
            
            offset = frame_end
        
        # 查找DATA帧和HEADERS帧
        data_frames = [f for f in frames if f['type'] == 0x0]
        headers_frames = [f for f in frames if f['type'] == 0x1]
        
        # 处理DATA帧，获取准确的数据长度
        data_length = None
        modified_data = None
        
        if data_frames:
            data_frame = data_frames[0]
            modified_data, json_length = process_http2_data_frame(data_frame['data'], modifications)
            if modified_data:
                data_length = len(modified_data)
            else:
                data_length = data_frame['length']
                modified_data = data_frame['data']
                
            logger.info(f"DATA帧长度: {data_length}")
        
        # 首先检查HEADERS帧中是否包含content-length
        has_content_length = False
        content_length_value = None
        
        for frame in headers_frames:
            headers = get_http2_headers(frame['data'])
            if 'content-length' in headers:
                has_content_length = True
                content_length_value = int(headers['content-length'])
                logger.info(f"HEADERS帧包含content-length: {content_length_value}")
                break
        
        # 如果存在content-length字段和DATA帧，检查是否需要修正
        if has_content_length and data_length is not None and content_length_value != data_length:
            logger.warning(f"content-length不匹配: headers={content_length_value}, data={data_length}")
        
        # 根据帧类型处理并重建所有帧
        new_payload = b''
        for frame in frames:
            if frame['type'] == 0x1:  # HEADERS帧
                headers = get_http2_headers(frame['data'])
                
                # 先处理URL路径和authority
                modified_headers = process_http2_headers_frame(frame['data'], context_num)
                
                # 如果有content-length，确保它与DATA帧长度一致
                if 'content-length' in headers and data_length is not None:
                    modified_headers = set_headers_content_length(modified_headers, data_length)
                
                if modified_headers != frame['data']:
                    frame_header = frame['header']
                    frame_header.length = len(modified_headers)
                    new_payload += bytes(frame_header.build()) + modified_headers
                else:
                    new_payload += raw[frame['offset']:frame['end']]
            elif frame['type'] == 0x0:  # DATA帧
                if modified_data and modified_data != frame['data']:
                    frame_header = frame['header']
                    frame_header.length = len(modified_data)
                    new_payload += bytes(frame_header.build()) + modified_data
                else:
                    new_payload += raw[frame['offset']:frame['end']]
            else:
                # 其他帧保持不变
                new_payload += raw[frame['offset']:frame['end']]
        
        return new_payload
    except Exception as e:
        logger.error(f"处理特定报文错误: {str(e)}", exc_info=True)
        return raw

def is_http2_packet(raw):
    """检测是否为HTTP/2报文"""
    try:
        if len(raw) < 9:
            return False
            
        # 检查第一个帧的类型
        frame_header = HTTP2FrameHeader(raw[0:9])
        return frame_header.type in [0x0, 0x1, 0x4, 0x8]  # 常见的HTTP/2帧类型
    except:
        return False

def check_content_length_mismatch(raw):
    """检查报文中是否存在content-length与DATA帧长度不匹配的情况"""
    try:
        # 提取HEADERS帧中的content-length和DATA帧长度
        content_length = None
        data_length = None
        
        offset = 0
        while offset + 9 <= len(raw):
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if frame_header is None:
                break
                
            if frame_type == 0x1:  # HEADERS帧
                headers = get_http2_headers(frame_data)
                if 'content-length' in headers:
                    content_length = int(headers['content-length'])
            elif frame_type == 0x0:  # DATA帧
                data_length = frame_len
                
            offset = frame_end
        
        # 返回是否存在不匹配情况及实际DATA帧长度
        if content_length is not None and data_length is not None:
            return content_length != data_length, data_length, content_length
        return False, None, None
    except Exception as e:
        logger.error(f"检查content-length匹配错误: {str(e)}")
        return False, None, None

def process_packet(pkt, modifications, seq_diff, ip_replacements, context_num, packet_count):
    """
    对 TCP 包内部的 HTTP/2 数据帧进行处理：
    1. 解析所有 HTTP/2 帧，修改 HEADERS 帧中的 path 和 authority。
    2. 对 DATA 帧进行 JSON 数据修改。
    3. 修改五元组 IP 地址对。
    4. 确保content-length与DATA帧长度一致。
    5. 根据包内负载变化计算偏移量，累加调整 TCP 序号。
    6. 删除校验和字段，让 Scapy 自动重新生成。
    """
    if pkt.haslayer(IP):
        # 修改五元组 IP 地址对
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
        new_payload = None

        # 只对SYN/FIN/RST以外的有效payload包做处理
        if has_payload and not (is_syn or is_fin or is_rst):
            raw = bytes(pkt[Raw].load)
            
            # 检查是否是HTTP/2报文
            if is_http2_packet(raw):
                # 检查是否存在content-length不匹配问题
                has_mismatch, data_length, content_length = check_content_length_mismatch(raw)
                
                if has_mismatch:
                    logger.warning(f"数据包#{packet_count}: 发现content-length不匹配报文: headers={content_length}, data={data_length}")
                    logger.info(f"数据包#{packet_count}: {pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}")
                    
                # 专门处理所有HTTP/2报文，确保content-length与DATA帧长度一致
                new_payload = process_specific_packet(raw, context_num, modifications)
            else:
                # 非HTTP/2报文，保持原样
                new_payload = raw

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
            # 累计序号差异
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
    PCAP_OUT = "pcap/N16_fixed_v3.pcap"   # 输出 PCAP 文件路径

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

    logger.info(f"开始处理文件 {PCAP_IN}")
    
    try:
        packets = rdpcap(PCAP_IN)
        logger.info(f"成功读取 {len(packets)} 个数据包")
    except Exception as e:
        logger.error(f"读取PCAP文件失败: {str(e)}")
        return

    modified_packets = []

    # 保存每个流累计的 TCP 序号偏移量
    seq_diff = {}
    # 初始化context编号
    context_num = 1000000001
    # 数据包计数
    packet_count = 0

    # 处理每个数据包
    for pkt in packets:
        try:
            packet_count += 1
            if TCP in pkt or Raw in pkt:
                process_packet(pkt, MODIFICATIONS, seq_diff, IP_REPLACEMENTS, context_num, packet_count)
                # 每处理一个包，context_num递增
                context_num += 1
            modified_packets.append(pkt)
        except Exception as e:
            logger.error(f"数据包#{packet_count}处理错误: {str(e)}", exc_info=True)
            modified_packets.append(pkt)  # 保留原始包

    logger.info(f"保存修改后的 PCAP 到 {PCAP_OUT}")
    try:
        wrpcap(PCAP_OUT, modified_packets)
        logger.info("PCAP文件保存成功")
    except Exception as e:
        logger.error(f"保存PCAP文件失败: {str(e)}")

if __name__ == "__main__":
    main() 