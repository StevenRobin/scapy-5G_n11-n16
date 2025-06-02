from scapy.all import rdpcap, wrpcap, TCP, Raw
from hpack import Decoder, Encoder

def modify_headers_from_pcap(input_pcap, output_pcap, target_indices=[9, 13], auth2="60.0.0.1", pduSessionId2="10000001"):
    """
    修改PCAP文件中指定报文的HTTP/2头部字段（HPACK解码/编码方式）
    
    Args:
        input_pcap: 输入PCAP文件路径
        output_pcap: 输出PCAP文件路径
        target_indices: 目标报文编号列表
        auth2: 新的authority值（不包含端口）
        pduSessionId2: 新的PDU Session ID
    
    Returns:
        bool: 修改是否成功
    """
    # 检查输入文件是否存在
    if not os.path.exists(input_pcap):
        print(f"错误: 输入文件 {input_pcap} 不存在")
        return False
    
    try:
        packets = rdpcap(input_pcap)
        print(f"✓ 成功读取 {len(packets)} 个数据包")
    except Exception as e:
        print(f"✗ 读取PCAP文件失败: {e}")
        return False
    
    decoder = Decoder()
    encoder = Encoder()
    modified_packets = 0
    modification_log = []
    for idx, pkt in enumerate(packets, 1):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        raw_data = bytes(pkt[Raw].load)
        # 解析HTTP/2帧
        offset = 24 if raw_data.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n') else 0
        while offset + 9 <= len(raw_data):
            length = int.from_bytes(raw_data[offset:offset+3], 'big')
            type_ = raw_data[offset+3]
            flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], 'big') & 0x7FFFFFFF
            payload = raw_data[offset+9:offset+9+length]
            if type_ == 0x01 and idx in target_indices:  # HEADERS帧且目标报文
                try:
                    # 解码原始头部，保留顺序
                    headers = decoder.decode(payload)
                    new_headers = []
                    mod_log = []
                    for name, value in headers:
                        name_str = name.decode() if isinstance(name, bytes) else name
                        value_str = value.decode() if isinstance(value, bytes) else value
                        if name_str == ":authority":
                            if value_str != auth2:
                                mod_log.append(f":authority: {value_str} → {auth2}")
                                value_str = auth2
                        elif name_str == ":path":
                            import re
                            new_path = value_str
                            m = re.match(r"(/nsmf-pdusession/v1/pdu-sessions/)(\d+)(.*)", value_str)
                            if m:
                                new_path = m.group(1) + str(pduSessionId2) + m.group(3)
                                if value_str != new_path:
                                    mod_log.append(f":path: {value_str} → {new_path}")
                                    value_str = new_path
                        new_headers.append((name_str, value_str))
                    # 重新HPACK编码，替换payload
                    new_payload = encoder.encode(new_headers)
                    # 构造新raw_data
                    new_raw = bytearray(raw_data)
                    new_raw[offset+9:offset+9+length] = new_payload
                    # 更新长度字段
                    new_len = len(new_payload)
                    new_raw[offset:offset+3] = new_len.to_bytes(3, 'big')
                    pkt[Raw].load = bytes(new_raw)
                    modified_packets += 1
                    modification_log.append({'packet_index': idx, 'modifications': mod_log})
                except Exception as e:
                    print(f"报文{idx} HPACK处理异常: {e}")
            offset += 9 + length

    wrpcap(output_pcap, packets)
    print(f"✓ 共修改了 {modified_packets} 个数据包，保存到 {output_pcap}")
    # 可选：写日志
    # ...

# 用法示例
# modify_headers_from_pcap("N16_release_18p.pcap", "N16_modified_headers.pcap")
