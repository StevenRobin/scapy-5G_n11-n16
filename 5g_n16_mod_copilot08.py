from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re
import copy

class HTTP2FrameHeader(Packet):
    name = "HTTP2FrameHeader"
    fields_desc = [
        BitField("length", 0, 24),
        ByteField("type", 0),
        ByteField("flags", 0),
        BitField("reserved", 0, 1),
        BitField("stream_id", 0, 31)
    ]

def extract_http2_frame_header(raw, offset):
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

def extract_json_from_frame(frame_data):
    json_data = None
    metadata = None
    
    # 处理multipart数据
    if b"--++Boundary" in frame_data:
        parts = re.split(br'(--\+\+Boundary)', frame_data)
        for i in range(len(parts)):
            if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                if b"Content-Type:application/json" in parts[i + 1]:
                    segments = parts[i + 1].split(b"\r\n\r\n", 1)
                    if len(segments) == 2:
                        metadata = segments[0]
                        try:
                            # 只解析不修改
                            payload = segments[1].strip()
                            if payload:
                                json_data = json.loads(payload)
                        except Exception as e:
                            print(f"JSON解析错误: {str(e)}")
        return {"type": "multipart", "boundary_parts": parts, "json_data": json_data, "metadata": metadata}
    else:
        try:
            # 尝试直接作为JSON解析
            if frame_data.strip():
                json_data = json.loads(frame_data)
                return {"type": "json", "json_data": json_data}
        except Exception as e:
            # 不是JSON数据，直接返回原始数据
            return {"type": "raw", "data": frame_data}

def extract_headers_from_frame(frame_data):
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        return headers
    except Exception as e:
        print(f"Header解析错误: {str(e)}")
        return None

def analyze_tcp_flow(packets):
    flows = {}
    packet_info = []
    flow_seq_info = {}  # 存储每个流的序列号信息
    
    for i, pkt in enumerate(packets):
        if IP in pkt and TCP in pkt:
            # 提取基本信息
            pkt_data = {
                "index": i,
                "packet": pkt,  # 存储原始包引用
                "ip_src": pkt[IP].src,
                "ip_dst": pkt[IP].dst,
                "tcp_sport": pkt[TCP].sport,
                "tcp_dport": pkt[TCP].dport,
                "tcp_seq": pkt[TCP].seq,
                "tcp_ack": pkt[TCP].ack if hasattr(pkt[TCP], 'ack') else None,
                "tcp_flags": pkt[TCP].flags,
                "has_payload": Raw in pkt and len(pkt[Raw].load) > 0,
                "payload_len": len(pkt[Raw].load) if Raw in pkt else 0,
                "frames": [],
                "modifications": [],
                "fields_to_modify": []  # 记录需要修改的字段
            }
            
            # 流标识：源IP、目的IP、源端口、目的端口
            flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            if flow not in flows:
                flows[flow] = []
                flow_seq_info[flow] = {"next_seq": pkt[TCP].seq}  # 初始化序列号信息
            
            # 更新流的序列号信息
            if pkt_data["has_payload"]:
                flow_seq_info[flow]["next_seq"] = (pkt[TCP].seq + pkt_data["payload_len"]) & 0xFFFFFFFF
            elif pkt[TCP].flags & 0x02:  # SYN包
                flow_seq_info[flow]["next_seq"] = (pkt[TCP].seq + 1) & 0xFFFFFFFF
            elif pkt[TCP].flags & 0x01:  # FIN包
                flow_seq_info[flow]["next_seq"] = (pkt[TCP].seq + 1) & 0xFFFFFFFF
            
            flows[flow].append(pkt_data)
            
            # 对于有效负载的包，解析HTTP2帧
            if pkt_data["has_payload"]:
                raw_data = bytes(pkt[Raw].load)
                offset = 0
                
                # 解析所有HTTP2帧
                while offset < len(raw_data):
                    if offset + 9 > len(raw_data):
                        # 剩余数据不足以形成帧头
                        frame_info = {
                            "type": "incomplete",
                            "data": raw_data[offset:],
                            "offset": offset
                        }
                        pkt_data["frames"].append(frame_info)
                        break
                    
                    frame_header, frame_len, frame_type, frame_data, frame_end = extract_http2_frame_header(raw_data, offset)
                    if frame_header is None:
                        break
                    
                    frame_info = {
                        "header": frame_header,
                        "type": frame_type,
                        "data": frame_data,
                        "offset": offset,
                        "end": frame_end,
                        "content": None
                    }
                    
                    # 根据帧类型解析内容
                    if frame_type == 0x0:  # DATA
                        frame_info["content"] = extract_json_from_frame(frame_data)
                    elif frame_type == 0x1:  # HEADERS
                        frame_info["content"] = extract_headers_from_frame(frame_data)
                    
                    pkt_data["frames"].append(frame_info)
                    offset = frame_end
            
            packet_info.append(pkt_data)
    
    return packet_info, flows, flow_seq_info

def find_json_fields_to_modify(json_data, modifications, path=""):
    """递归查找需要修改的JSON字段，返回路径和修改信息"""
    fields_to_modify = []
    
    if json_data is None:
        return fields_to_modify
    
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            current_path = f"{path}.{key}" if path else key
            
            # 检查是否是需要修改的字段
            if key in modifications:
                fields_to_modify.append({
                    "path": current_path,
                    "old_value": value,
                    "new_value": modifications[key],
                    "key": key
                })
            
            # 递归检查嵌套字段
            if isinstance(value, (dict, list)):
                sub_fields = find_json_fields_to_modify(value, modifications, current_path)
                fields_to_modify.extend(sub_fields)
                
    elif isinstance(json_data, list):
        for i, item in enumerate(json_data):
            current_path = f"{path}[{i}]"
            if isinstance(item, (dict, list)):
                sub_fields = find_json_fields_to_modify(item, modifications, current_path)
                fields_to_modify.extend(sub_fields)
                
    return fields_to_modify

def find_fields_to_modify(packet_info, modifications, new_path, new_authority):
    """查找所有需要修改的字段，而不立即修改"""
    
    for pkt_data in packet_info:
        # 检查IP替换
        if pkt_data["ip_src"] in IP_REPLACEMENTS:
            pkt_data["ip_src_new"] = IP_REPLACEMENTS[pkt_data["ip_src"]]
        if pkt_data["ip_dst"] in IP_REPLACEMENTS:
            pkt_data["ip_dst_new"] = IP_REPLACEMENTS[pkt_data["ip_dst"]]
        
        # 处理帧内容
        if pkt_data["has_payload"]:
            for frame in pkt_data["frames"]:
                if "type" in frame and frame["type"] == "incomplete":
                    continue
                
                frame_type = frame["type"]
                
                # 检查DATA帧中的JSON数据
                if frame_type == 0x0 and "content" in frame:
                    content = frame["content"]
                    if content is not None and "type" in content:
                        if content["type"] == "multipart" and content["json_data"]:
                            # 查找multipart中的JSON字段
                            json_fields = find_json_fields_to_modify(content["json_data"], modifications)
                            if json_fields:
                                frame["fields_to_modify"] = {
                                    "type": "json",
                                    "fields": json_fields,
                                    "json_type": "multipart",
                                    "boundary_parts": content["boundary_parts"],
                                    "metadata": content["metadata"]
                                }
                        elif content["type"] == "json" and content["json_data"]:
                            # 查找纯JSON字段
                            json_fields = find_json_fields_to_modify(content["json_data"], modifications)
                            if json_fields:
                                frame["fields_to_modify"] = {
                                    "type": "json",
                                    "fields": json_fields,
                                    "json_type": "plain",
                                    "json_data": content["json_data"]
                                }
                
                # 检查HEADERS帧
                elif frame_type == 0x1 and "content" in frame:
                    headers = frame["content"]
                    if headers:
                        header_changes = []
                        for i, (name, value) in enumerate(headers):
                            if name == ":path" and new_path:
                                header_changes.append({
                                    "index": i,
                                    "name": name,
                                    "old_value": value,
                                    "new_value": new_path
                                })
                            elif name == ":authority" and new_authority:
                                header_changes.append({
                                    "index": i,
                                    "name": name,
                                    "old_value": value,
                                    "new_value": new_authority
                                })
                        
                        if header_changes:
                            frame["fields_to_modify"] = {
                                "type": "headers",
                                "changes": header_changes,
                                "headers": headers
                            }

def apply_modifications(packet_info, flow_seq_info):
    """应用所有修改并重建数据包"""
    new_flow_seq_info = copy.deepcopy(flow_seq_info)  # 复制原始序列号信息
    modified_flow_map = {}  # 记录修改后的数据流序列号映射
    
    # 第一遍：应用修改并计算每个数据包的长度变化
    for pkt_data in packet_info:
        flow = (pkt_data["ip_src"], pkt_data["ip_dst"], pkt_data["tcp_sport"], pkt_data["tcp_dport"])
        rev_flow = (pkt_data["ip_dst"], pkt_data["ip_src"], pkt_data["tcp_dport"], pkt_data["tcp_sport"])
        
        if flow not in modified_flow_map:
            modified_flow_map[flow] = {
                "seq_base": pkt_data["tcp_seq"],  # 原始基准序列号
                "seq_offset": 0,                 # 累积序列号偏移
                "next_seq": pkt_data["tcp_seq"]  # 下一个预期序列号
            }
        
        if rev_flow not in modified_flow_map:
            # 如果反向流不存在，先初始化，具体值将在处理反向包时更新
            modified_flow_map[rev_flow] = {
                "seq_base": 0,
                "seq_offset": 0,
                "next_seq": 0
            }
        
        # 跳过SYN/FIN/RST包的内容修改
        if pkt_data["has_payload"]:
            flags = pkt_data["tcp_flags"]
            is_syn = flags & 0x02 != 0
            is_fin = flags & 0x01 != 0
            is_rst = flags & 0x04 != 0
            
            if not (is_syn or is_fin or is_rst):
                total_diff = 0
                new_payload = b''
                
                # 重建帧
                for frame in pkt_data["frames"]:
                    # 处理不完整帧
                    if "type" in frame and frame["type"] == "incomplete":
                        new_payload += frame["data"]
                        continue
                    
                    frame_header = frame["header"]
                    frame_data = frame["data"]
                    modified_data = None
                    
                    # 应用修改
                    if "fields_to_modify" in frame:
                        mod_info = frame["fields_to_modify"]
                        
                        # 修改JSON
                        if mod_info["type"] == "json":
                            if mod_info["json_type"] == "multipart":
                                # 应用multipart中的JSON修改
                                json_data = copy.deepcopy(frame["content"]["json_data"])
                                for field in mod_info["fields"]:
                                    # 使用递归路径设置值
                                    path_parts = field["path"].split(".")
                                    current = json_data
                                    for i, part in enumerate(path_parts):
                                        # 处理数组索引
                                        if '[' in part and ']' in part:
                                            key, idx_str = part.split('[', 1)
                                            idx = int(idx_str.rstrip(']'))
                                            if i == len(path_parts) - 1:
                                                current[key][idx] = field["new_value"]
                                            else:
                                                current = current[key][idx]
                                        else:
                                            if i == len(path_parts) - 1:
                                                current[part] = field["new_value"]
                                                pkt_data["modifications"].append({
                                                    "path": field["path"],
                                                    "old": field["old_value"],
                                                    "new": field["new_value"]
                                                })
                                            else:
                                                current = current[part]
                                
                                # 重建multipart
                                parts = mod_info["boundary_parts"]
                                for i in range(len(parts)):
                                    if parts[i] == b"--++Boundary" and i + 1 < len(parts):
                                        if b"Content-Type:application/json" in parts[i + 1]:
                                            segments = parts[i + 1].split(b"\r\n\r\n", 1)
                                            if len(segments) == 2:
                                                # 使用修改后的JSON替换原始JSON
                                                json_str = json.dumps(json_data, separators=(',', ':')).encode()
                                                parts[i + 1] = segments[0] + b"\r\n\r\n" + json_str
                                
                                modified_data = b''.join(parts)
                            
                            elif mod_info["json_type"] == "plain":
                                # 应用纯JSON修改
                                json_data = copy.deepcopy(frame["content"]["json_data"])
                                for field in mod_info["fields"]:
                                    # 使用递归路径设置值
                                    path_parts = field["path"].split(".")
                                    current = json_data
                                    for i, part in enumerate(path_parts):
                                        # 处理数组索引
                                        if '[' in part and ']' in part:
                                            key, idx_str = part.split('[', 1)
                                            idx = int(idx_str.rstrip(']'))
                                            if i == len(path_parts) - 1:
                                                current[key][idx] = field["new_value"]
                                            else:
                                                current = current[key][idx]
                                        else:
                                            if i == len(path_parts) - 1:
                                                current[part] = field["new_value"]
                                                pkt_data["modifications"].append({
                                                    "path": field["path"],
                                                    "old": field["old_value"],
                                                    "new": field["new_value"]
                                                })
                                            else:
                                                current = current[part]
                                
                                modified_data = json.dumps(json_data, separators=(',', ':')).encode()
                        
                        # 修改Headers
                        elif mod_info["type"] == "headers":
                            headers = copy.deepcopy(mod_info["headers"])
                            # 确保headers有效
                            valid_headers = []
                            for h in headers:
                                if isinstance(h, tuple) and len(h) == 2:
                                    valid_headers.append(h)
                                else:
                                    print(f"[警告] 跳过无效头部: {h}")
                            
                            headers = valid_headers
                            
                            for change in mod_info["changes"]:
                                idx = change["index"]
                                name = change["name"]
                                # 检查索引范围
                                if 0 <= idx < len(headers):
                                    headers[idx] = (name, change["new_value"])
                                    pkt_data["modifications"].append({
                                        "field": name,
                                        "old": change["old_value"],
                                        "new": change["new_value"]
                                    })
                                else:
                                    print(f"[警告] 头部索引超出范围: {idx}, 最大值: {len(headers)-1}")
                            
                            try:
                                encoder = Encoder()
                                modified_data = encoder.encode(headers)
                            except Exception as e:
                                print(f"[错误] 头部编码失败: {e}")
                                # 使用原始数据继续
                                modified_data = None
                    
                    # 应用帧修改
                    if modified_data:
                        old_len = len(frame_data)
                        new_len = len(modified_data)
                        frame_diff = new_len - old_len
                        total_diff += frame_diff
                        
                        # 更新帧头长度
                        frame_header.length = new_len
                        new_payload += frame_header.build() + modified_data
                    else:
                        # 无修改，保留原始帧
                        new_payload += frame_header.build() + frame_data
                
                # 存储新payload并记录长度差异
                if total_diff != 0:
                    pkt_data["payload_diff"] = total_diff
                    pkt_data["new_payload"] = new_payload
                    pkt_data["new_payload_len"] = len(new_payload)
                    
                    # 更新流的序列号偏移
                    modified_flow_map[flow]["seq_offset"] += total_diff
                    
                    print(f"[+] 包 {pkt_data['index']} 修改: 原始长度={pkt_data['payload_len']}, 新长度={pkt_data['new_payload_len']}, 差异={total_diff}")
    
    # 第二遍：更新所有数据包的序列号和确认号
    for pkt_data in packet_info:
        flow = (pkt_data["ip_src"], pkt_data["ip_dst"], pkt_data["tcp_sport"], pkt_data["tcp_dport"])
        rev_flow = (pkt_data["ip_dst"], pkt_data["ip_src"], pkt_data["tcp_dport"], pkt_data["tcp_sport"])
        
        # 检查是否是SYN、FIN或RST包
        flags = pkt_data["tcp_flags"]
        is_syn = flags & 0x02 != 0
        is_fin = flags & 0x01 != 0
        is_rst = flags & 0x04 != 0
        
        # 计算序列号偏移
        # 如果当前序列号大于等于流的基准序列号，则应用偏移
        flow_map = modified_flow_map[flow]
        seq_diff = 0
        
        # 仅对于SYN和含有负载的数据包更新next_seq
        if is_syn:
            flow_map["next_seq"] = (pkt_data["tcp_seq"] + 1) & 0xFFFFFFFF
        elif pkt_data["has_payload"]:
            # 使用原始包的序列号作为当前包的序列号
            pkt_data["new_seq"] = flow_map["next_seq"]
            
            # 计算下一个包的序列号
            payload_len = pkt_data.get("new_payload_len", pkt_data["payload_len"])
            flow_map["next_seq"] = (pkt_data["new_seq"] + payload_len) & 0xFFFFFFFF
        else:
            # 对于没有负载的包，保持序列号不变但考虑偏移
            pkt_data["new_seq"] = pkt_data["tcp_seq"]
            
            # FIN包消耗一个序列号
            if is_fin:
                flow_map["next_seq"] = (pkt_data["tcp_seq"] + 1) & 0xFFFFFFFF
        
        # 处理确认号
        if pkt_data["tcp_ack"] is not None:
            rev_flow_map = modified_flow_map[rev_flow]
            if "next_seq" in rev_flow_map and rev_flow_map["next_seq"] > 0:
                # 使用反向流的next_seq作为确认号
                pkt_data["new_ack"] = rev_flow_map["next_seq"]
            else:
                # 如果反向流还未初始化，使用原始确认号
                pkt_data["new_ack"] = pkt_data["tcp_ack"]
    
    return packet_info

def build_modified_packets(packet_info):
    modified_packets = []
    
    for pkt_data in packet_info:
        orig_pkt = pkt_data["packet"]
        # 创建一个新包，避免修改原始包
        new_pkt = orig_pkt.copy()
        
        # 应用IP修改
        if IP in new_pkt:
            if "ip_src_new" in pkt_data:
                print(f"[+] 替换源IP {new_pkt[IP].src} -> {pkt_data['ip_src_new']}")
                new_pkt[IP].src = pkt_data["ip_src_new"]
            if "ip_dst_new" in pkt_data:
                print(f"[+] 替换目的IP {new_pkt[IP].dst} -> {pkt_data['ip_dst_new']}")
                new_pkt[IP].dst = pkt_data["ip_dst_new"]
        
        # 应用TCP修改
        if TCP in new_pkt:
            # 更新序列号
            if "new_seq" in pkt_data:
                new_pkt[TCP].seq = pkt_data["new_seq"]
            
            # 更新确认号
            if "new_ack" in pkt_data and pkt_data["new_ack"]:
                new_pkt[TCP].ack = pkt_data["new_ack"]
            
            # 更新负载
            if "new_payload" in pkt_data and Raw in new_pkt:
                print(f"[+] 更新TCP负载: 包 {pkt_data['index']}, 原始长度={len(orig_pkt[Raw].load)}, 新长度={len(pkt_data['new_payload'])}")
                new_pkt[Raw].load = pkt_data["new_payload"]
                
                # 记录所有修改
                for mod in pkt_data["modifications"]:
                    if "path" in mod:
                        print(f"[+] 修改JSON字段: {mod['path']} = {mod['old']} -> {mod['new']}")
                    elif "field" in mod:
                        print(f"[+] 修改HTTP头: {mod['field']} = {mod['old']} -> {mod['new']}")
        
        # 清除校验和，让Scapy重新计算
        if hasattr(new_pkt[IP], 'chksum'):
            del new_pkt[IP].chksum
        if TCP in new_pkt and hasattr(new_pkt[TCP], 'chksum'):
            del new_pkt[TCP].chksum
        if hasattr(new_pkt[IP], 'len'):
            del new_pkt[IP].len
        
        # 更新包长度
        new_pkt.wirelen = len(new_pkt)
        new_pkt.caplen = new_pkt.wirelen
        
        modified_packets.append(new_pkt)
    
    return modified_packets

# --- 主处理流程 ---
PCAP_IN = "pcap/N16_create_16p.pcap"
PCAP_OUT = "pcap/N16_174.pcap"

MODIFICATIONS = {
    "supi": "imsi-460012300000001",
    "pei": "imeisv-8611101000000011",
    "gpsi": "msisdn-8613900000001",
    "dnn": "dnn1234567",
    "ismfId": "c251849c-681e-48ba-918b-000010000001",
    "icnTunnelInfo": {"ipv4Addr": "10.0.0.1", "gtpTeid": "10000001"},
    "cnTunnelInfo": {"ipv4Addr": "20.0.0.1", "gtpTeid": "50000001"},
    "ueIpv4Address": "100.0.0.1",
    "nrCellId": "010000001",
    "uplink": "5000000000",
    "downlink": "5000000000",
    "ismfPduSessionUri": "http://30.0.0.1:80/nsmf-pdusession/v1/pdu-sessions/100000001"
}
IP_REPLACEMENTS = {
    "200.20.20.26": "30.0.0.1",
    "200.20.20.25": "40.0.0.1"
}

print(f"开始处理文件 {PCAP_IN}")
packets = rdpcap(PCAP_IN)

print(f"[1] 分析TCP流和HTTP2帧")
packet_info, flows, flow_seq_info = analyze_tcp_flow(packets)

print(f"[2] 查找需要修改的字段")
new_path = "/nsmf-pdusession/v1/sm-contexts/1000000001/retrieve"
new_authority = "smf.smf"
find_fields_to_modify(packet_info, MODIFICATIONS, new_path, new_authority)

print(f"[3] 应用修改并重建帧")
packet_info = apply_modifications(packet_info, flow_seq_info)

print(f"[4] 生成修改后的数据包")
modified_packets = build_modified_packets(packet_info)

print(f"保存修改后的 PCAP 到 {PCAP_OUT}")
wrpcap(PCAP_OUT, modified_packets)
print(f"处理完成，已保存到 {PCAP_OUT}")