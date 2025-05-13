from scapy.all import rdpcap, TCP
from hpack import Decoder

def parse_http2_frames(payload):
    i = 0
    frames = []
    while i + 9 <= len(payload):
        length = int.from_bytes(payload[i:i+3], 'big')
        frame_type = payload[i+3]
        flags = payload[i+4]
        stream_id = int.from_bytes(payload[i+5:i+9], 'big') & 0x7FFFFFFF
        fragment = payload[i+9:i+9+length]
        frames.append((frame_type, flags, stream_id, fragment, i, length))
        i += 9 + length
    return frames

def main():
    pcap_file = 'pcap/N16_143.pcap'
    packets = rdpcap(pcap_file)

    # 只拼接 src=12346, dst=80 方向的payload
    tcp_payloads = []
    for pkt in packets:
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            if t.sport == 12346 and t.dport == 80 and len(t.payload) > 0:
                tcp_payloads.append(bytes(t.payload))
    http2_stream = b''.join(tcp_payloads)

    frames = parse_http2_frames(http2_stream)

    decoder = Decoder()
    print('All HEADERS frames in src=12346->dst=80:')
    for idx, (frame_type, flags, stream_id, fragment, offset, length) in enumerate(frames):
        if frame_type == 0x1:  # HEADERS
            try:
                headers = dict(decoder.decode(fragment))
            except Exception as e:
                headers = {}
            print(f'HEADERS frame {idx}, offset={offset}, stream_id={stream_id}, content-length={headers.get("content-length")}, headers={headers}')

if __name__ == '__main__':
    main()