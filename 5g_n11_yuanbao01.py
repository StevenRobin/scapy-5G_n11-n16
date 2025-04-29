import json


def parse_hexdump(hexdump_text):
    packets = []
    current_packet = bytearray()
    lines = hexdump_text.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            if current_packet:
                packets.append(bytes(current_packet))
                current_packet = bytearray()
            continue
        hex_part = line[6:6 + 16 * 3].strip()
        bytes_in_line = hex_part.split()
        for b_str in bytes_in_line:
            current_packet.append(int(b_str, 16))
    if current_packet:
        packets.append(bytes(current_packet))
    return packets


def parse_packet(packet):
    if len(packet) < 14:
        return None
    eth_type = packet[12:14]
    if eth_type != b'\x08\x00':
        return None
    ip_packet = packet[14:]
    if len(ip_packet) < 20:
        return None
    ip_ihl = ip_packet[0] & 0x0F
    ip_header_length = ip_ihl * 4
    if len(ip_packet) < ip_header_length:
        return None
    total_length = int.from_bytes(ip_packet[2:4], byteorder='big')
    ip_packet = ip_packet[:total_length]
    protocol = ip_packet[9]
    if protocol != 6:
        return None
    tcp_segment = ip_packet[ip_header_length:]
    if len(tcp_segment) < 20:
        return None
    data_offset = (tcp_segment[12] >> 4) & 0x0F
    tcp_header_length = data_offset * 4
    if len(tcp_segment) < tcp_header_length:
        return None
    return tcp_segment[tcp_header_length:]


def modify_json(data):
    if isinstance(data, dict):
        if 'icnTunnelInfo' in data:
            icn = data['icnTunnelInfo']
            if isinstance(icn, dict):
                icn['ipv4Addr'] = '10.0.0.1'
                icn['gtpTeid'] = 'A0000001'
        if 'cnTunnelInfo' in data:
            cn = data['cnTunnelInfo']
            if isinstance(cn, dict):
                cn['ipv4Addr'] = '20.0.0.1'
                cn['gtpTeid'] = 'B0000001'
        for key in list(data.keys()):
            if key == 'supi':
                data[key] = 'imsi-46003010000002'
            elif key == 'pei':
                data[key] = 'imeisv-1031014000012222'
            elif key == 'gpsi':
                data[key] = 'msisdn-8615910012222'
            elif key == 'ueIpv4Address':
                data[key] = '100.0.0.1'
            else:
                modify_json(data[key])
    elif isinstance(data, list):
        for item in data:
            modify_json(item)


def main(hexdump_text):
    packets = parse_hexdump(hexdump_text)
    tcp_payloads = []
    for p in packets:
        payload = parse_packet(p)
        if payload:
            tcp_payloads.append(payload)
    full_stream = b''.join(tcp_payloads)
    magic = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    magic_pos = full_stream.find(magic)
    http2_data = full_stream[magic_pos + len(magic):] if magic_pos != -1 else full_stream

    pos = 0
    while pos < len(http2_data):
        if pos + 9 > len(http2_data):
            break
        length = int.from_bytes(http2_data[pos:pos + 3], 'big')
        type_ = http2_data[pos + 3]
        flags = http2_data[pos + 4]
        stream_id = int.from_bytes(http2_data[pos + 5:pos + 9], 'big') & 0x7FFFFFFF
        end_pos = pos + 9 + length
        if end_pos > len(http2_data):
            break
        frame_payload = http2_data[pos + 9:end_pos]
        pos = end_pos

        if type_ == 0x0 and (flags & 0x1):
            try:
                json_str = frame_payload.decode('utf-8', errors='ignore')
                json_data = json.loads(json_str)
                modify_json(json_data)
                print(json.dumps(json_data, indent=2))
            except:
                continue


if __name__ == "__main__":
    # 示例用法（需替换为实际hexdump文本）
    hexdump_text = """
    0000  00 0c 29 8b 27 e9 00 0c 29 8b 27 e9 08 00 45 00   ..).'...).'...E.
    ... [其余hexdump数据] ...
    """
    main(hexdump_text)