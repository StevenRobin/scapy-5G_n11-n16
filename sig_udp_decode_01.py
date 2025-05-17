import sys
import struct
import socket
from scapy.all import rdpcap, UDP
import datetime

def hexstr(val, width):
    if val is None:
        return "None"
    return f"0x{val:0{width}x}"

def ip_from_bytes(b):
    return socket.inet_ntoa(b)

def parse_main_fields(payload):
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
            res[name] = (None, None)
            continue
        if fmt.endswith('s'):
            bval = payload[offset:offset+size]
            res[name] = (bval.hex(), bval.hex())
        else:
            val = struct.unpack_from(fmt, payload, offset)[0]
            res[name] = (hexstr(val, hexw), val)
    return res

def parse_tlv(payload, start_offset):
    tlvs = []
    offset = start_offset
    while offset + 2 <= len(payload):
        tlv_type = payload[offset]
        tlv_len = payload[offset+1]
        if offset + 2 + tlv_len > len(payload):
            break
        tlv_value = payload[offset+2:offset+2+tlv_len]
        tlv = {
            "type": tlv_type,
            "length": tlv_len,
            "raw_value": tlv_value,
        }
        if tlv_type == 0x02 and tlv_len == 8:
            ip_bytes = tlv_value[:4]
            val_bytes = tlv_value[4:8]
            tlv["desc"] = f"IPv4 Address: {ip_from_bytes(ip_bytes)}"
            tlv["value"] = f"{val_bytes.hex()} [IPv4 + Value]"
        elif tlv_type == 0x07 and tlv_len == 4:
            ip_bytes = tlv_value[:4]
            tlv["desc"] = f"IPv4 Address: {ip_from_bytes(ip_bytes)}"
            tlv["value"] = None
        else:
            tlv["desc"] = None
            tlv["value"] = tlv_value.hex()
        tlvs.append(tlv)
        offset += 2 + tlv_len
    return tlvs

def format_capture_time(val):
    if val is None:
        return "None"
    seconds = val // 1_000_000
    useconds = val % 1_000_000
    t = datetime.datetime.utcfromtimestamp(seconds)
    t_str = t.strftime("%b %d, %Y %H:%M:%S")
    return f"{t_str}.{useconds:06d} UTC"

def main():
    if len(sys.argv) != 2:
        print("Usage: python sig_udp_decode_01.py xxx.pcap")
        sys.exit(1)
    pcap_file = sys.argv[1]
    packets = rdpcap(pcap_file)
    matched_packets = []
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(UDP):
            continue
        udp_payload = bytes(pkt[UDP].payload)
        print(f"Packet #{i+1} UDP payload (len={len(udp_payload)}): {udp_payload[:16].hex()}")
        if len(udp_payload) < 65:
            continue
        packet_mark = struct.unpack_from(">I", udp_payload, 0)[0]   # 用大端
        print(f"  magic value: 0x{packet_mark:08x}")
        if packet_mark != 0x9a8b7c6d:
            continue
        fields = parse_main_fields(udp_payload)
        tlvs = parse_tlv(udp_payload, 65)
        matched_packets.append((i+1, fields, tlvs))

    if not matched_packets:
        print("No matching UDP packets found (payload magic not matched).")
        return

    for pidx, fields, tlvs in matched_packets:
        print(f"\nPacket #{pidx}:")
        for k, (hx, dv) in fields.items():
            if k == "Capture_time":
                print(f"  {k}: {hx} ({format_capture_time(dv)})")
            elif k == "Tai":
                print(f"  {k}: {hx}")
            else:
                print(f"  {k}: {hx} ({dv})")
        print("  TLVs:")
        for idx, tlv in enumerate(tlvs, 1):
            print(f"    TLV {idx}: Type=0x{tlv['type']:02x}, Length={tlv['length']}")
            if tlv["desc"]: print(f"      {tlv['desc']}")
            if tlv["value"]: print(f"      Value: {tlv['value']}")
        if not tlvs:
            print("    (none)")

if __name__ == "__main__":
    main()