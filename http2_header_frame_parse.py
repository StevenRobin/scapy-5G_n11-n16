import scapy.all as scapy
import hpack

def parse_http2_frames(data):
    frames = []
    offset = 0
    while offset + 9 <= len(data):
        length = int.from_bytes(data[offset:offset+3], 'big')
        type = data[offset+3]
        flags = data[offset+4]
        stream_id = int.from_bytes(data[offset+5:offset+9], 'big') & 0x7fffffff
        frame_data = data[offset+9:offset+9+length]
        frames.append({
            "type": type,
            "flags": flags,
            "stream_id": stream_id,
            "data": frame_data
        })
        offset += 9 + length
    return frames

packets = scapy.rdpcap("pcap/N16_create_16p.pcap")
decoder = hpack.Decoder()
packet_idx = 0
for pkt in packets:
    packet_idx += 1
    if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
        payload = bytes(pkt["Raw"].load)
        frames = parse_http2_frames(payload)
        for frame in frames:
            if frame["type"] == 0x1:  # HEADERS
                try:
                    headers = decoder.decode(frame["data"])
                    print(f"Packet #{packet_idx}: HEADERS frame")
                    for k, v in headers:
                        print("   ", k, v)
                except Exception as e:
                    print(f"Error decoding HEADERS in packet {packet_idx}: {e}")