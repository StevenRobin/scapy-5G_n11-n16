from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re
import copy

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
        # 跳过空数据段
        if not payload.strip():
            print("[跳过空数据段]")
            return None
        data = json.loads(payload)
        modified = False

        def recursive_modify(obj, modifications):
            """递归修改嵌套 JSON 对象"""
            nonlocal modified
            if isinstance(obj, dict):
                for key, value in obj.items():
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
        return json.dumps(data, separators=(',', ':')).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def process_http2_data_frame(frame_data, modifications):
    """处理 HTTP/2 DATA 帧中的多部分数据，并返回实际的JSON数据长度"""
    json_length = 0
    modified_data = None

    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
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

def process_http2_headers_frame(frame_data, packet_idx, context_num, data_length=None):
    """处理 HTTP/2 HEADERS 帧，根据报文索引修改特定字段"""
    try:
        # 确保所有HTTP/2头部都能被解析
        decoder = Decoder()
        encoder = Encoder()
        headers = decoder.decode(frame_data)
        modified = False
        new_headers = []
        
        # 保留所有原始头部，并修改特定字段
        for name, value in headers:
            # 修改特定报文的特定字段
            if packet_idx == 9:  # 第9个报文
                if name == ":path":
                    new_path = f"/nsmf-pdusession/v1/sm-contexts/{context_num}/retrieve"
                    print(f"[+] 修改第{packet_idx}个报文 header {name}: {value} -> {new_path}")
                    new_headers.append((name, new_path))
                    modified = True
                    continue
                elif name == ":authority":
                    new_authority = "smf.smf"
                    print(f"[+] 修改第{packet_idx}个报文 header {name}: {value} -> {new_authority}")
                    new_headers.append((name, new_authority))
                    modified = True
                    continue
            elif packet_idx == 13:  # 第13个报文
                if name == ":authority":
                    new_authority = "smf.smf"
                    print(f"[+] 修改第{packet_idx}个报文 header {name}: {value} -> {new_authority}")
                    new_headers.append((name, new_authority))
                    modified = True
                    continue
            elif packet_idx == 15:  # 第15个报文
                if name == "location":
                    authority = "smf.smf"
                    new_location = f"http://{authority}/nsmf-pdusession/v1/pdu-sessions/{context_num}"
                    print(f"[+] 修改第{packet_idx}个报文 header {name}: {value} -> {new_location}")
                    new_headers.append((name, new_location))
                    modified = True
                    continue
            
            # 排除content-length字段，稍后单独处理
            if name.lower() != "content-length":
                new_headers.append((name, value))

        # 如果有DATA帧并且需要更新content-length
        if data_length is not None and data_length > 0:
            print(f"[+] 设置第{packet_idx}个报文 content-length: {data_length}")
            new_headers.append(("content-length", str(data_length)))
            modified = True

        if modified:
            return encoder.encode(new_headers)
        return frame_data
    except Exception as e:
        print(f"Header处理错误: {str(e)}")
        return frame_data

def store_original_packet_info(packets):
    """存储原始报文信息，用于后续修改和for循环生成多个PCAP"""
    original_info = []
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            info = {
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'sport': pkt[TCP].sport,
                'dport': pkt[TCP].dport,
                'seq': pkt[TCP].seq,
                'ack': pkt[TCP].ack if hasattr(pkt[TCP], 'ack') else None,
                'flags': pkt[TCP].flags,
                'has_payload': pkt.haslayer(Raw) and len(pkt[Raw].load) > 0,
                'payload': bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None,
                # 添加HTTP/2帧相关信息（如果有）
                'http2_frames': extract_http2_frames(pkt) if pkt.haslayer(Raw) else []
            }
            original_info.append(info)
        else:
            # 保存非TCP/IP包的基本信息
            original_info.append({'is_tcp_ip': False, 'original_pkt': copy.deepcopy(pkt)})
    return original_info

def extract_http2_frames(pkt):
    """从数据包中提取HTTP/2帧信息，便于后续处理"""
    frames = []
    if not pkt.haslayer(Raw):
        return frames
    
    raw = bytes(pkt[Raw].load)
    offset = 0
    
    while offset < len(raw):
        if offset + 9 > len(raw):
            break
            
        frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
        if frame_header is None:
            break
            
        frame_info = {
            'type': frame_type,
            'length': frame_len,
            'data': frame_data,
            'offset': offset,
            'end': frame_end
        }
        
        # 对特定类型的帧添加更多信息
        if frame_type == 0x1:  # HEADERS帧
            try:
                decoder = Decoder()
                headers = decoder.decode(frame_data)
                frame_info['headers'] = headers
            except Exception as e:
                print(f"提取HTTP/2头部错误: {str(e)}")
                
        frames.append(frame_info)
        offset = frame_end
        
    return frames

def process_packet(pkt, modifications, seq_diff, ip_replacements, context_num, packet_idx):
    """
    对 TCP 包内部的 HTTP/2 数据帧进行处理：
    1. 解析所有 HTTP/2 帧，根据报文索引修改特定字段。
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

        # 只对SYN/FIN/RST以外的有效payload包做累计
        if has_payload and not (is_syn or is_fin or is_rst):
            raw = bytes(pkt[Raw].load)
            offset = 0
            new_payload = b''
            json_length = None
            has_headers = False
            has_data = False
            data_frame_info = None

            # 第一遍扫描：查找DATA帧并获取JSON长度
            current_offset = 0
            while current_offset < len(raw):
                if current_offset + 9 > len(raw):
                    break
                frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, current_offset)
                if frame_header is None:
                    break
                if frame_type == 0x1:  # HEADERS帧
                    has_headers = True
                elif frame_type == 0x0:  # DATA帧
                    has_data = True
                    # 保存DATA帧信息以供后续处理
                    data_frame_info = (frame_data, frame_len)
                current_offset = frame_end

            # 如果找到DATA帧，先处理它以获取实际的JSON长度
            if data_frame_info:
                frame_data, _ = data_frame_info
                _, json_length = process_http2_data_frame(frame_data, modifications)

            # 第二遍扫描：处理所有帧
            while offset < len(raw):
                if offset + 9 > len(raw):
                    new_payload += raw[offset:]
                    offset = len(raw)
                    break

                frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
                if frame_header is None:
                    break

                if frame_type == 0x1:  # HEADERS帧
                    # 只有当包中同时存在HEADERS和DATA帧时才设置content-length
                    current_json_length = json_length if has_data else None
                    modified_frame_data = process_http2_headers_frame(frame_data, packet_idx, context_num, current_json_length)
                    if modified_frame_data:
                        frame_len = len(modified_frame_data)
                        frame_header.length = frame_len
                        new_payload += frame_header.build() + modified_frame_data
                        offset = frame_end
                        continue
                elif frame_type == 0x0:  # DATA帧
                    modified_frame_data, _ = process_http2_data_frame(frame_data, modifications)
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

def generate_modified_pcap(original_info, modifications, ip_replacements, base_context_num, output_file):
    """基于原始报文信息生成修改后的PCAP文件"""
    modified_packets = []
    seq_diff = {}
    context_num = base_context_num
    
    for idx, info in enumerate(original_info, 1):
        if 'is_tcp_ip' in info and not info['is_tcp_ip']:
            # 直接添加非TCP/IP包
            modified_packets.append(info['original_pkt'])
            continue
            
        # 重建报文
        ip_layer = IP(src=info['src_ip'], dst=info['dst_ip'])
        tcp_layer = TCP(sport=info['sport'], dport=info['dport'], 
                        seq=info['seq'], flags=info['flags'])
        if info['ack'] is not None:
            tcp_layer.ack = info['ack']
            
        pkt = ip_layer/tcp_layer
        if info['has_payload']:
            pkt = pkt/Raw(load=info['payload'])
            
        # 处理报文
        process_packet(pkt, modifications, seq_diff, ip_replacements, context_num, idx)
        modified_packets.append(pkt)
        
        # 更新context_num
        context_num += 1
        
    # 写入PCAP文件
    wrpcap(output_file, modified_packets)
    print(f"保存修改后的 PCAP 到 {output_file}")
    return modified_packets

def generate_multiple_pcaps(original_info, modifications_list, ip_replacements, base_context_num, output_pattern):
    """
    基于原始报文信息批量生成多个修改后的PCAP文件
    每个PCAP使用modifications_list中的不同修改内容
    """
    for i, modifications in enumerate(modifications_list):
        output_file = output_pattern.format(i+1)
        print(f"\n开始生成第{i+1}个PCAP: {output_file}")
        
        current_context_num = base_context_num + i * 1000  # 每批次context_num递增
        generate_modified_pcap(original_info, modifications, ip_replacements, current_context_num, output_file)
        
    print(f"批量生成完成，共{len(modifications_list)}个PCAP文件")

# ---------------------- 主处理流程 ----------------------
PCAP_IN = "pcap/N16_create_16p.pcap"   # 输入 PCAP 文件路径
PCAP_OUT = "pcap/N16_0519004.pcap"   # 输出 PCAP 文件路径

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

def main():
    """主函数，用于处理单个PCAP文件"""
    print(f"开始处理文件 {PCAP_IN}")
    packets = rdpcap(PCAP_IN)

    # 存储原始报文信息
    original_info = store_original_packet_info(packets)
    print(f"已存储 {len(original_info)} 个原始报文的信息")

    # 保存原始报文信息到文件，便于后续使用
    with open("original_packet_info.json", "w") as f:
        # 转换为可序列化格式
        serializable_info = []
        for info in original_info:
            if 'is_tcp_ip' in info and not info['is_tcp_ip']:
                # 非TCP/IP包无法直接序列化，记录类型信息
                serializable_info.append({'is_tcp_ip': False})
                continue
            # 移除无法序列化的payload和http2_frames字段
            serializable_item = {k: v for k, v in info.items() 
                              if k not in ['payload', 'http2_frames', 'original_pkt']}
            # 修复flags字段的序列化问题
            if 'flags' in serializable_item:
                try:
                    serializable_item['flags'] = int(serializable_item['flags'])
                except Exception:
                    serializable_item['flags'] = str(serializable_item['flags'])
            serializable_info.append(serializable_item)
        json.dump(serializable_info, f, indent=2)
        print("已保存可序列化的报文信息到 original_packet_info.json")

    # 生成修改后的PCAP文件
    base_context_num = 1000000001
    modified_packets = generate_modified_pcap(original_info, MODIFICATIONS, IP_REPLACEMENTS, 
                                            base_context_num, PCAP_OUT)

    print(f"处理完成，共修改 {len(modified_packets)} 个报文")
    
    # 演示如何使用批量生成功能
    # modifications_list = []
    # 可以在这里添加多个不同的修改配置
    # for i in range(3):
    #     mod_copy = copy.deepcopy(MODIFICATIONS)
    #     mod_copy["supi"] = f"imsi-46001230000000{i+1}"
    #     modifications_list.append(mod_copy)
    # generate_multiple_pcaps(original_info, modifications_list, IP_REPLACEMENTS, 
    #                         base_context_num, "pcap/N16_batch_{}.pcap")

if __name__ == "__main__":
    main()