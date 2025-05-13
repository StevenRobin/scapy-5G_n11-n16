from scapy.all import rdpcap, TCP

def parse_http2_data_frame_lengths_and_real_lengths(tcp_payload):
    """
    返回[(length字段, 真实payload长度), ...]
    """
    i = 0
    result = []
    while i + 9 <= len(tcp_payload):
        length = int.from_bytes(tcp_payload[i:i+3], 'big')
        frame_type = tcp_payload[i+3]
        # 只处理DATA帧（type=0x0）
        if frame_type == 0:
            # payload可能不够长，防止出错
            real_len = min(length, len(tcp_payload) - (i + 9))
            result.append((length, real_len))
        i += 9 + length
    return result

def main():
    pcap_file = 'pcap/N16_modified130.pcap'
    packets = rdpcap(pcap_file)
    idxs = [10, 12, 14]  # 0-based, 第11、13、15个包

    for idx in idxs:
        pkt = packets[idx]
        frames = []
        if pkt.haslayer(TCP):
            tcp_payload = bytes(pkt[TCP].payload)
            frames = parse_http2_data_frame_lengths_and_real_lengths(tcp_payload)
        print(f'Packet #{idx+1}:')
        for j, (length_field, real_len) in enumerate(frames):
            print(f'  DATA frame #{j+1}: length field = {length_field}, real payload length = {real_len}')
        if not frames:
            print('  No HTTP/2 DATA frames found.')

if __name__ == '__main__':
    main()