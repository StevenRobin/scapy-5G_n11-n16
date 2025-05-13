from scapy.all import rdpcap, TCP

def parse_http2_frame_length(tcp_payload):
    # HTTP/2帧格式：前3字节长度，1字节类型，1字节flags，4字节stream id
    # 这里只简单抓DATA帧（type=0x0）
    i = 0
    lengths = []
    while i + 9 <= len(tcp_payload):
        length = int.from_bytes(tcp_payload[i:i+3], 'big')
        frame_type = tcp_payload[i+3]
        # frame_type==0表示DATA帧
        if frame_type == 0:
            lengths.append(length)
        i += 9 + length
    return lengths

def main():
    pcap_file = 'pcap/N16_modified130.pcap'
    packets = rdpcap(pcap_file)
    idxs = [10, 12, 14]  # 0-based, 第11、13、15个包

    for idx in idxs:
        pkt = packets[idx]
        content_lengths = []
        if pkt.haslayer(TCP):
            tcp_payload = bytes(pkt[TCP].payload)
            content_lengths = parse_http2_frame_length(tcp_payload)
        print(f'Packet #{idx+1} HTTP/2 DATA frame lengths: {content_lengths}')

if __name__ == '__main__':
    main()