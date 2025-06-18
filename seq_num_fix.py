from scapy.all import rdpcap, wrpcap, TCP, IP

def get_flow_key(pkt):
    """根据IP和TCP端口区分流方向，返回流的唯一key和方向"""
    if IP in pkt and TCP in pkt:
        src = (pkt[IP].src, pkt[TCP].sport)
        dst = (pkt[IP].dst, pkt[TCP].dport)
        # 用更小（src, dst）为正向
        if src < dst:
            return (src, dst), 'up'
        else:
            return (dst, src), 'down'
    return None, None

def fix_seq(input_pcap, output_pcap):
    packets = rdpcap(input_pcap)
    flow_seq = {}  # {flow_key: {"up": seq, "down": seq}}
    new_packets = []

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            flow_key, direction = get_flow_key(pkt)
            if flow_key is None:
                new_packets.append(pkt)
                continue

            if flow_key not in flow_seq:
                flow_seq[flow_key] = {"up": 0, "down": 0}

            # 获取原始长度（不含TCP header）
            payload_len = len(pkt[TCP].payload)
            # 更新seq
            pkt[TCP].seq = flow_seq[flow_key][direction]
            # 下一包起始seq
            flow_seq[flow_key][direction] += payload_len
            # 需要重新计算校验和
            del pkt[TCP].chksum
            del pkt[IP].chksum
            pkt = pkt.__class__(bytes(pkt))
        new_packets.append(pkt)

    wrpcap(output_pcap, new_packets)
    print(f"新pcap已保存到: {output_pcap}")

if __name__ == "__main__":
    # 用法示例
    input_pcap = "pcap/N11_release_18p.pcap"
    output_pcap = "pcap/N11_release_18p_seqfix.pcap"
    fix_seq(input_pcap, output_pcap)