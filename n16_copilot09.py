from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder
import json
import re
import copy

def store_original_packet_info(packets):
    """
    存储每个包的原始信息（如有必要，还可存储payload和http2帧等）
    返回一个列表，每个元素是一个字典，描述一个包的关键信息
    """
    packet_infos = []
    for idx, pkt in enumerate(packets):
        info = {
            "idx": idx,
            "is_tcp_ip": pkt.haslayer(IP) and pkt.haslayer(TCP),
            "src": pkt[IP].src if pkt.haslayer(IP) else None,
            "dst": pkt[IP].dst if pkt.haslayer(IP) else None,
            "sport": pkt[TCP].sport if pkt.haslayer(TCP) else None,
            "dport": pkt[TCP].dport if pkt.haslayer(TCP) else None,
            "flags": int(pkt[TCP].flags) if pkt.haslayer(TCP) and pkt[TCP].flags is not None else None,
            "seq": pkt[TCP].seq if pkt.haslayer(TCP) else None,
            "ack": pkt[TCP].ack if pkt.haslayer(TCP) and hasattr(pkt[TCP], 'ack') else None,
            "payload": bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None,
            # 可扩展http2解析内容等
        }
        packet_infos.append(info)
    return packet_infos

class HTTP2FrameHeader(Packet):
    name = "HTTP2FrameHeader"
    fields_desc = [
        BitField("length", 0, 24),
        ByteField("type", 0),
        ByteField("flags", 0),
        BitField("reserved", 0, 1),
        BitField("stream_id", 0, 31)
    ]

def parse_http2_frames(raw):
    """
    解析raw数据为HTTP2帧的列表，每个元素为字典，包含frame_header, frame_type, frame_data, frame_offset等
    """
    frames = []
    offset = 0
    while offset + 9 <= len(raw):
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        frame_end = offset + 9 + frame_len
        if frame_end > len(raw):
            frame_end = len(raw)
            frame_len = frame_end - (offset + 9)
            frame_header.length = frame_len
        frame_data = raw[offset + 9:frame_end]
        frames.append({
            "frame_header": frame_header,
            "frame_type": frame_type,
            "frame_data": frame_data,
            "offset": offset,
            "frame_end": frame_end
        })
        offset = frame_end
    if offset < len(raw):
        frames.append({
            "frame_header": None,
            "frame_type": None,
            "frame_data": raw[offset:],
            "offset": offset,
            "frame_end": len(raw)
        })
    return frames

def modify_http2_headers(headers, modifications):
    """
    通用header修改函数，modifications为dict: {":authority": "smf.smf", ":path": "/xxx", "location": "xxxx"}
    """
    modified = False
    new_headers = []
    for name, value in headers:
        if name in modifications:
            print(f"[+] 修改 header {name}: {value} -> {modifications[name]}")
            new_headers.append((name, modifications[name]))
            modified = True
        else:
            new_headers.append((name, value))
    return new_headers, modified

def decode_http2_headers(frame_data):
    decoder = Decoder()
    headers = decoder.decode(frame_data)
    return headers

def encode_http2_headers(headers):
    encoder = Encoder()
    return encoder.encode(headers)

def modify_json_data(payload, modifications):
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
        # 使用 separators=(',', ':') 保证无多余空格
        return json.dumps(data, separators=(',', ':')).encode() if modified else None
    except Exception as e:
        print(f"JSON处理错误: {str(e)}")
        return None

def update_content_length_in_headers(headers, content_length):
    """
    更新content-length字段
    """
    updated = False
    new_headers = []
    for name, value in headers:
        if name.lower() == "content-length":
            print(f"[+] 更新 content-length: {value} -> {content_length}")
            new_headers.append((name, str(content_length)))
            updated = True
        else:
            new_headers.append((name, value))
    return new_headers, updated

def process_packet(pkt, seq_diff, ip_replacements, modifications, pkt_idx,
                   mod_headers_map, mod_header_extra_map, orig_pkt_info):
    # 原始IP地址字段替换
    if pkt.haslayer(IP):
        if pkt[IP].src in ip_replacements:
            pkt[IP].src = ip_replacements[pkt[IP].src]
        if pkt[IP].dst in ip_replacements:
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

        if has_payload and not (is_syn or is_fin or is_rst):
            raw = bytes(pkt[Raw].load)
            orig_pkt_info[pkt_idx]["raw"] = raw

            frames = parse_http2_frames(raw)
            orig_pkt_info[pkt_idx]["frames"] = copy.deepcopy(frames)

            # 记录所有headers类型帧的解码内容
            for i, frame in enumerate(frames):
                if frame["frame_type"] == 0x1:
                    try:
                        headers = decode_http2_headers(frame["frame_data"])
                        orig_pkt_info[pkt_idx].setdefault("headers_decoded", []).append(headers)
                    except Exception as e:
                        orig_pkt_info[pkt_idx].setdefault("headers_decoded", []).append([])

            # 需要修改header的报文
            mod_headers = mod_headers_map.get(pkt_idx, {})
            mod_header_extra = mod_header_extra_map.get(pkt_idx, {})

            # 标记并缓存第一个content-length头部的索引
            first_content_length_idx = None
            for i, frame in enumerate(frames):
                # 只处理headers类型帧
                if frame["frame_type"] == 0x1:
                    try:
                        headers = decode_http2_headers(frame["frame_data"])
                        if mod_headers:
                            headers, changed = modify_http2_headers(headers, mod_headers)
                        if mod_header_extra:
                            headers, changed2 = modify_http2_headers(headers, mod_header_extra)
                        # 记录第一个content-length头
                        for idx, (key, val) in enumerate(headers):
                            if key.lower() == "content-length" and first_content_length_idx is None:
                                first_content_length_idx = (i, idx)
                        frame["frame_data"] = encode_http2_headers(headers)
                        frame["frame_header"].length = len(frame["frame_data"])
                    except Exception as e:
                        pass
            # 处理data帧，json修改并同步content-length
            data_length_modified = None
            for i, frame in enumerate(frames):
                if frame["frame_type"] == 0x0:
                    # 处理json
                    modified = modify_json_data(frame["frame_data"], modifications)
                    if modified:
                        frame["frame_data"] = modified
                        frame["frame_header"].length = len(modified)
                        data_length_modified = len(modified)
            # 更新content-length
            if data_length_modified and first_content_length_idx:
                headers = decode_http2_headers(frames[first_content_length_idx[0]]["frame_data"])
                headers, updated = update_content_length_in_headers(headers, data_length_modified)
                frames[first_content_length_idx[0]]["frame_data"] = encode_http2_headers(headers)
                frames[first_content_length_idx[0]]["frame_header"].length = len(
                    frames[first_content_length_idx[0]]["frame_data"])

            # 合成payload
            new_payload = b""
            for frame in frames:
                if frame["frame_header"] is not None:
                    new_payload += frame["frame_header"].build() + frame["frame_data"]
                else:
                    new_payload += frame["frame_data"]

            original_length = len(raw)
            new_length = len(new_payload)
            diff = new_length - original_length
            pkt[Raw].load = new_payload

            # 修正seq/ack
            pkt[TCP].seq = pkt[TCP].seq + seq_diff[flow]
            if pkt[TCP].flags & 0x10 and hasattr(pkt[TCP], 'ack'):
                pkt[TCP].ack = pkt[TCP].ack + seq_diff[rev_flow]
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

def generate_modified_pcap(original_info, modifications, ip_replacements, base_context_num, pcap_out_path):
    """
    根据原始报文信息和修改参数生成新的PCAP文件
    返回修改后的packet列表
    """
    # 重新读取原始PCAP，逐包处理
    packets = rdpcap(PCAP_IN)
    seq_diff = {}

    # 定义需要修改HTTP2头部的报文索引和字段
    mod_headers_map = {
        8: {":authority": "smf.smf", ":path": "/nsmf-pdusession/v1/sm-contexts/1000000001/retrieve"}, # 第9包
        12: {":authority": "smf.smf"}, # 第13包
    }
    mod_header_extra_map = {
        14: {"location": "smf.smf"}, # 第15包
    }

    orig_pkt_info = [{} for _ in range(len(packets))]

    modified_packets = []
    for idx, pkt in enumerate(packets):
        process_packet(pkt, seq_diff, ip_replacements, modifications, idx, mod_headers_map, mod_header_extra_map, orig_pkt_info)
        modified_packets.append(pkt)

    wrpcap(pcap_out_path, modified_packets)
    return modified_packets

PCAP_IN = "pcap/N16_create_16p.pcap"  # 输入 PCAP 文件路径
PCAP_OUT = "pcap/N16_1003.pcap"  # 输出 PCAP 文件路径

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
    "ismfPduSessionUri": "http://30.0.0.1:80/nsmf-pdusession/v1/pdu-sessions/10000001"
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
                serializable_info.append({'is_tcp_ip': False})
                continue
            serializable_item = {}
            for k, v in info.items():
                if k in ['payload', 'http2_frames', 'original_pkt']:
                    continue
                # 处理 flags 字段
                if k == "flags":
                    serializable_item[k] = int(v) if v is not None else None
                else:
                    serializable_item[k] = v
            serializable_info.append(serializable_item)

        json.dump(serializable_info, f, indent=2)
        print("已保存可序列化的报文信息到 original_packet_info.json")

    # 生成修改后的PCAP文件
    base_context_num = 1000000001
    modified_packets = generate_modified_pcap(original_info, MODIFICATIONS, IP_REPLACEMENTS,
                                              base_context_num, PCAP_OUT)

    print(f"处理完成，共修改 {len(modified_packets)} 个报文")

    # 如果需要批量生成，可参考如下（注释掉，解开可用）
    # modifications_list = []
    # for i in range(3):
    #     mod_copy = copy.deepcopy(MODIFICATIONS)
    #     mod_copy["supi"] = f"imsi-46001230000000{i+1}"
    #     modifications_list.append(mod_copy)
    # generate_multiple_pcaps(original_info, modifications_list, IP_REPLACEMENTS,
    #                         base_context_num, "pcap/N16_batch_{}.pcap")

if __name__ == "__main__":
    main()