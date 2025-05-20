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
            "data": frame_data,
            "offset": offset,
            "length": length
        })
        offset += 9 + length
    return frames

def modify_location_host_in_headers(headers, new_host):
    new_headers = []
    for k, v in headers:
        k_str = k.decode("utf8")
        if k_str.lower() == "location":
            v_str = v.decode("utf8")
            parts = v_str.split("/", 3)
            if len(parts) >= 3:
                parts[2] = new_host
                new_value = "/".join(parts)
            else:
                new_value = v_str
            print(f"old location: {v_str}")
            print(f"new location: {new_value}")
            new_headers.append((k, new_value.encode("utf8")))
        else:
            new_headers.append((k, v))
    return new_headers

def extract_modify_and_save_pcap(pcap_path, new_host, target_packet=15, out_pcap="pcap/n16_modLocation_01.pcap"):
    packets = scapy.rdpcap(pcap_path)
    decoder = hpack.Decoder()
    encoder = hpack.Encoder()
    count = 0

    mod_packets = packets[:]

    for idx, pkt in enumerate(mod_packets):
        if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
            count += 1
            if count == target_packet:
                payload = bytes(pkt["Raw"].load)
                frames = parse_http2_frames(payload)
                new_payload = bytearray(payload)
                changed = False

                for frame in frames:
                    if frame["type"] == 0x1:
                        try:
                            headers = decoder.decode(frame["data"])
                            print("Original headers:")
                            for k, v in headers:
                                print("   ", k, v)
                            new_headers = modify_location_host_in_headers(headers, new_host)
                            encoded = encoder.encode(new_headers)
                            print("\nEncoded new HEADERS frame (hex):")
                            print(encoded.hex())
                            print("\nNew headers after modification:")
                            for k, v in new_headers:
                                print("   ", k, v)
                            # 替换payload中的HEADERS帧内容
                            start = frame["offset"] + 9
                            end = frame["offset"] + 9 + frame["length"]
                            # 对于长度不一致，需要整体移位或补0（此处假设只替换，不增加header数量/长度不会变化太大）
                            # 如果长度不同，需要整体调整TCP payload
                            orig_len = frame["length"]
                            new_len = len(encoded)
                            if new_len == orig_len:
                                new_payload[start:end] = encoded
                                new_payload[frame["offset"]:frame["offset"]+3] = new_len.to_bytes(3, "big")
                            elif new_len < orig_len:
                                # 填充0
                                new_payload[start:start+new_len] = encoded
                                new_payload[start+new_len:end] = b'\0' * (orig_len - new_len)
                                new_payload[frame["offset"]:frame["offset"]+3] = new_len.to_bytes(3, "big")
                            else:
                                # new payload更长，需要整体扩展payload并调整后续内容（此处给出简单报错提示）
                                print("Error: new HEADERS太长，不能直接替换！请减少location长度或手动重组payload。")
                                return
                            changed = True
                        except Exception as e:
                            print("HPACK decode error:", e)
                if changed:
                    pkt["Raw"].load = bytes(new_payload)
                    del pkt["TCP"].chksum
                    if pkt.haslayer("IP"):
                        del pkt["IP"].chksum
                    print(f"Modified location in packet #{idx+1} (Raw TCP packet #{count})")
                else:
                    print("No HEADERS frame with location found in target packet.")

    scapy.wrpcap(out_pcap, mod_packets)
    print(f"\nModified pcap saved as: {out_pcap}")

if __name__ == "__main__":
    pcap_file = "pcap/N16_create_16p.pcap"
    new_host = "10.10.10.10:8000"
    out_pcap = "pcap/n16_modLocation_01.pcap"
    extract_modify_and_save_pcap(pcap_file, new_host, target_packet=15, out_pcap=out_pcap)