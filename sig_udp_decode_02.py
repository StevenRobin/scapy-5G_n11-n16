import sys
import struct
import socket
import datetime
from scapy.all import rdpcap, UDP

def format_hex(val, width):
    if val is None:
        return "None"
    return f"0x{val:0{width}x}"

def format_capture_time(val):
    if val is None:
        return "None"
    seconds = val // 1_000_000
    useconds = val % 1_000_000
    t = datetime.datetime.utcfromtimestamp(seconds)
    t_str = t.strftime("%b %d, %Y %H:%M:%S")
    return f"{t_str}.{useconds:06d} UTC"

def parse_main_fields(payload):
    # 字段名, 偏移, 长度, 格式, hex宽度
    table = [
        ("Packet_mark",      0,  4,  ">I", 8),
        ("Flag",             4,  1,  ">B", 2),
        ("Message_len",      5,  2,  ">H", 4),
        ("Sequence_num",     7,  4,  ">I", 8),
        ("Isp_id",          11,  1,  ">B", 2),
        ("Interface",       12,  1,  ">B", 2),
        ("Rat_type",        13,  1,  ">B", 2),
        ("Rroceudre_type",  14,  1,  ">B", 2),
        ("Iot_flag",        15,  1,  ">B", 2),
        ("Capture_time",    16,  8,  ">Q", 16),
        ("Front_device_id", 24,  1,  ">B", 2),
        ("City_id",         25,  2,  ">H", 4),
        ("Imsi",            27,  8,  ">Q", 16),
        ("Imei_esn_meid",   35,  8,  ">Q", 16),
        ("Msisdn",          43,  8,  ">Q", 16),
        ("Tai",             51,  6,  "6s", 12),  # 6 bytes, hex
        ("Ncgi",            57,  8,  ">Q", 16),
    ]
    res = {}
    for name, offset, size, fmt, hexw in table:
        if offset + size > len(payload):
            res[name] = "None"
            continue
        if fmt.endswith('s'):
            res[name] = "0x" + payload[offset:offset+size].hex()
        elif name == "Capture_time":
            val = struct.unpack_from(fmt, payload, offset)[0]
            res[name] = format_capture_time(val)
        else:
            val = struct.unpack_from(fmt, payload, offset)[0]
            res[name] = format_hex(val, hexw)
    return res

def main():
    if len(sys.argv) != 2:
        print("Usage: python sig_udp_decode_01.py xxx.pcap")
        sys.exit(1)
    pcap_file = sys.argv[1]
    packets = rdpcap(pcap_file)
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(UDP):
            continue
        udp_payload = bytes(pkt[UDP].payload)
        if len(udp_payload) < 65:
            continue
        packet_mark = struct.unpack_from(">I", udp_payload, 0)[0]
        if packet_mark != 0x9a8b7c6d:
            continue
        fields = parse_main_fields(udp_payload)
        print("-" * 60)
        for k, v in fields.items():
            print(f"{k} : {v}")
        print("-" * 60)
    else:
        if 'fields' not in locals():
            print("No matching UDP packets found (payload magic not matched).")

if __name__ == "__main__":
    main()