import scapy.all as scapy
import hpack

# ... 保持HPACK_STATIC_TABLE和parse_http2_frames不变 ...

def print_dynamic_table(pcap_path, debug=True):
    packets = scapy.rdpcap(pcap_path)
    tcp_payload_stream, pkt_index = reassemble_tcp_stream(packets)
    print("==== 动态表跟踪 ====")
    decoder = hpack.Decoder()
    frames = parse_http2_frames(tcp_payload_stream)
    print(f"[调试] 共解析出{len(frames)}个HTTP/2帧")
    frame_types = {0x1: "HEADERS", 0x9: "CONTINUATION"}
    for idx, frame in enumerate(frames):
        print(f"[调试] 帧#{idx+1} 类型={frame['type']} 长度={frame['length']} 流ID={frame['stream_id']}")
        if frame["type"] in (0x1, 0x9):
            try:
                headers = decoder.decode(frame["data"])
                print(f"\n[帧#{idx+1}] 类型: {frame_types.get(frame['type'], str(frame['type']))}, 流ID: {frame['stream_id']}")
                print("  解码到 headers:")
                for k, v in headers:
                    kstr = k.decode(errors='replace') if isinstance(k, bytes) else str(k)
                    vstr = v.decode(errors='replace') if isinstance(v, bytes) else str(v)
                    print(f"    {kstr}: {vstr}")
                print("\n  当前动态表:")
                if decoder.header_table:
                    for i, (name, value) in enumerate(decoder.header_table, 1):
                        n = name.decode(errors='replace') if isinstance(name, bytes) else str(name)
                        v = value.decode(errors='replace') if isinstance(value, bytes) else str(value)
                        print(f"    {i:2d}: {n} : {v}")
                else:
                    print("    (空)")
            except Exception as e:
                print(f"[帧#{idx+1}] 解码失败: {e}")

if __name__ == "__main__":
    pcap_file = "pcap/N16_create_16p.pcap"  # <-- 修改为你的pcap路径
    print_static_table()
    print("\n\n")
    print_dynamic_table(pcap_file)