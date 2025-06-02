import threading
import gc
from scapy.all import rdpcap, TCP, Raw, IP
from hpack import Decoder
import binascii
import re

# 变量初始化
auth2 = None
pduSessionId2 = 10000001
sip2 = None
dip2 = None

def extract_http2_frames(raw_data):
    """提取TCP包内所有HTTP/2帧 (返回frame_type, headers_block, offset)"""
    # 检查是否为HTTP/2前言
    if len(raw_data) >= 24 and raw_data.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'):
        # 这是HTTP/2前言，跳过前言部分
        offset = 24
    else:
        offset = 0
        
    frames = []
    while offset + 9 <= len(raw_data):
        length = int.from_bytes(raw_data[offset:offset+3], 'big')
        type_ = raw_data[offset+3]
        flags = raw_data[offset+4]
        stream_id = int.from_bytes(raw_data[offset+5:offset+9], 'big') & 0x7FFFFFFF
        
        if offset + 9 + length > len(raw_data):
            break  # 剩余数据不足
            
        frame_payload = raw_data[offset+9:offset+9+length]
        frames.append((type_, flags, stream_id, frame_payload, offset))
        offset += 9 + length
    return frames

def get_frame_type_name(type_id):
    """返回HTTP/2帧类型名称"""
    frame_types = {
        0x0: "DATA",
        0x1: "HEADERS",
        0x2: "PRIORITY",
        0x3: "RST_STREAM",
        0x4: "SETTINGS",
        0x5: "PUSH_PROMISE",
        0x6: "PING",
        0x7: "GOAWAY",
        0x8: "WINDOW_UPDATE",
        0x9: "CONTINUATION"
    }
    return frame_types.get(type_id, f"UNKNOWN({type_id})")

def extract_auth_and_pdu(headers):
    """从headers中提取auth和pduSessionId"""
    auth_val = None
    pdu_id = None
    for name, value in headers:
        name_str = name.decode('utf-8') if isinstance(name, bytes) else str(name)
        value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
        if name_str.lower() == "authorization":
            auth_val = value_str
        if name_str.lower() == ":path":
            # 匹配pdu-sessions/后面的数字
            m = re.search(r"pdu-sessions/(\d+)", value_str)
            if m:
                pdu_id = int(m.group(1))
    return auth_val, pdu_id

def print_selected_headers_from_pcap(pcap_file, target_indices=[9, 11, 13]):
    packets = rdpcap(pcap_file)
    
    # 为每个流维护一个解码器状态
    flow_decoders = {}  # (src_ip, src_port, dst_ip, dst_port) -> decoder
    
    for idx, pkt in enumerate(packets, 1):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
            
        # 识别流
        flow = None
        if pkt.haslayer(IP):
            flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        
        # 获取或创建解码器
        if flow and flow not in flow_decoders:
            flow_decoders[flow] = Decoder()
        
        decoder = flow_decoders.get(flow, Decoder())
        
        raw_data = bytes(pkt[Raw].load)
        frames = extract_http2_frames(raw_data)
        
        # 如果是目标包，打印详细信息帮助调试
        if idx in target_indices:
            print(f"\n==== 第{idx}个报文分析 ====")
            print(f"TCP流: {flow}")
            print(f"数据包长度: {len(raw_data)} 字节")
            print(f"识别的帧数: {len(frames)}")
            
            for frame_idx, (type_, flags, stream_id, payload, offset) in enumerate(frames):
                print(f"  帧 {frame_idx+1}: 类型={get_frame_type_name(type_)}, 长度={len(payload)}, "
                      f"标志=0x{flags:02x}, 流ID={stream_id}")
                
                # 尝试解码HEADERS帧
                if type_ == 0x01:  # HEADERS帧
                    try:
                        headers = decoder.decode(payload)
                        print(f"    HEADERS帧内容:")
                        for name, value in headers:
                            name_str = name.decode('utf-8') if isinstance(name, bytes) else str(name)
                            value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
                            print(f"      {name_str}: {value_str}")
                    except Exception as e:
                        print(f"    HEADERS帧解析失败: {str(e)}")
                        print(f"    十六进制数据: {binascii.hexlify(payload).decode()}")
        else:
            # 非目标包，只处理HEADERS帧更新解码器状态
            for type_, _, _, payload, _ in frames:
                if type_ == 0x01:  # HEADERS帧
                    try:
                        decoder.decode(payload)  # 只更新状态，不关心结果
                    except Exception:
                        pass  # 忽略非目标包的解析错误

def process_packet(pkt, idx, target_indices, flow_decoders, result_dict):
    global auth2, pduSessionId2, sip2, dip2
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    flow = None
    if pkt.haslayer(IP):
        flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)

    if flow and flow not in flow_decoders:
        flow_decoders[flow] = Decoder()
    decoder = flow_decoders.get(flow, Decoder())

    raw_data = bytes(pkt[Raw].load)
    frames = extract_http2_frames(raw_data)

    if idx in target_indices:
        for frame_idx, (type_, flags, stream_id, payload, offset) in enumerate(frames):
            if type_ == 0x01:  # HEADERS帧
                try:
                    headers = decoder.decode(payload)
                    auth_val, pdu_id = extract_auth_and_pdu(headers)
                    if auth_val:
                        auth2 = auth_val
                        dip2 = pkt[IP].dst
                    if pdu_id:
                        pduSessionId2 = pdu_id
                    sip2 = pkt[IP].src
                    # 记录结果
                    result_dict[idx] = {
                        "auth2": auth2,
                        "pduSessionId2": pduSessionId2,
                        "sip2": sip2,
                        "dip2": dip2
                    }
                except Exception:
                    pass

def process_pcap_multithread(pcap_file, target_indices=[9, 13]):
    packets = rdpcap(pcap_file)
    flow_decoders = {}
    threads = []
    result_dict = {}

    for idx, pkt in enumerate(packets, 1):
        t = threading.Thread(target=process_packet, args=(pkt, idx, target_indices, flow_decoders, result_dict))
        threads.append(t)
        t.start()
        # 控制线程数量，防止过多线程
        if len(threads) > 20:
            for t in threads:
                t.join()
            threads = []
            gc.collect()

    for t in threads:
        t.join()
    gc.collect()
    return result_dict

if __name__ == "__main__":
    pcap_path = "pcap/N16_release_18p.pcap"
    result = process_pcap_multithread(pcap_path)
    print("提取结果：")
    for idx in sorted(result):
        print(f"第{idx}包: {result[idx]}")
    print(f"\n最终变量：auth2={auth2}, pduSessionId2={pduSessionId2}, sip2={sip2}, dip2={dip2}")