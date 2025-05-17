import sys
import struct
import socket
import datetime
from scapy.all import rdpcap, UDP

MAIN_FIELDS = [
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
    ("Tai",             51,  6,  "6s", 12),
    ("Ncgi",            57,  8,  ">Q", 16),
]

TLV_ORDER = [
    (0x01, "PDU_ACTION"),
    (0x02, "UP_F_TEID"),
    (0x03, "DL_F_TEID"),
    (0x04, "PDU_SESSION_ID"),
    (0x05, "REMOVE_F_TEIDs"),
    (0x06, "PDU_SESSION_TYPE"),
    (0x07, "DYNAMICIPv4"),
    (0x08, "DYNAMICIPv6"),
    (0x09, "SNSSAI_SST"),
    (0x0a, "SNSSAI_SD"),
    (0x0b, "DNN"),
    (0x0c, "UE_ACTION"),
    (0x0d, "H0_TYPE"),
    (0x0e, "SRC_IPV4_ADDR"),
    (0x0f, "SRC_IPV6_ADDR"),
    (0x10, "DST_IPV4_ADDR"),
    (0x11, "DST_IPV6_ADDR"),
    (0x12, "ISP_MARKED_TIME"),
    (0x13, "MAC")
]
TLV_NAMES = dict(TLV_ORDER)

def format_capture_time(val):
    if val is None:
        return ""
    seconds = val // 1_000_000
    useconds = val % 1_000_000
    t = datetime.datetime.utcfromtimestamp(seconds)
    t_str = t.strftime("%b %d, %Y %H:%M:%S")
    return f"{t_str}.{useconds:06d} UTC"

def parse_main_fields(payload):
    res = {}
    for name, offset, size, fmt, hexw in MAIN_FIELDS:
        if offset + size > len(payload):
            res[name] = ""
            continue
        if fmt.endswith('s'):
            res[name] = "0x" + payload[offset:offset+size].hex()
        elif name == "Capture_time":
            val = struct.unpack_from(fmt, payload, offset)[0]
            res[name] = format_capture_time(val)
        else:
            val = struct.unpack_from(fmt, payload, offset)[0]
            res[name] = f"0x{val:0{hexw}x}"
    return res

def parse_single_tlv(tlv_type, tlv_value):
    if len(tlv_value) == 0:
        return ""
    if tlv_type in (0x02, 0x03):  # TEID(4字节)或更长
        return tlv_value.hex()
    elif tlv_type in (0x07, 0x0e, 0x10) and len(tlv_value) == 4:
        return socket.inet_ntoa(tlv_value)
    elif tlv_type in (0x08, 0x0f, 0x11) and len(tlv_value) == 16:
        return ":".join([tlv_value[i:i+2].hex() for i in range(0, 16, 2)])
    elif tlv_type == 0x12 and len(tlv_value) == 8:
        tval = struct.unpack(">Q", tlv_value)[0]
        return format_capture_time(tval)
    elif tlv_type == 0x13 and len(tlv_value) == 6:
        return ":".join(f"{b:02x}" for b in tlv_value)
    elif tlv_type == 0x0b:
        try:
            return tlv_value.decode(errors="replace")
        except:
            return tlv_value.hex()
    else:
        return tlv_value.hex()

def parse_tlv(payload, start_offset, end_offset=None):
    tlvs = []
    offset = start_offset
    payload_len = len(payload) if end_offset is None else end_offset
    while offset + 2 <= payload_len:
        tlv_type = payload[offset]
        tlv_len = payload[offset+1]
        if offset + 2 + tlv_len > payload_len:
            break
        tlv_value = payload[offset+2:offset+2+tlv_len]
        if tlv_type == 0x05 and tlv_len > 0:
            val = tlv_value.hex()  # 只显示原始hex
        else:
            val = parse_single_tlv(tlv_type, tlv_value) if tlv_len > 0 else ""
        tlvs.append((tlv_type, val))
        offset += 2 + tlv_len
    return tlvs

def print_aligned(rows, keycol=1, valcol=2, align_pos=44):
    # align_pos: value列起始位置（含序号和\t），建议40~48
    for row in rows:
        idx, key, val = row
        line = f"{idx}\t{key}"
        pad_len = align_pos - len(line.expandtabs())
        pad_len = max(1, pad_len)
        line += " " * pad_len
        if val:
            line += val
        print(line)

def main():
    if len(sys.argv) != 2:
        print("Usage: python sig_udp_decode_01.py xxx.pcap")
        sys.exit(1)
    pcap_file = sys.argv[1]
    packets = rdpcap(pcap_file)
    found = False
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(UDP):
            continue
        udp_payload = bytes(pkt[UDP].payload)
        if len(udp_payload) < 65:
            continue
        packet_mark = struct.unpack_from(">I", udp_payload, 0)[0]
        if packet_mark != 0x9a8b7c6d:
            continue
        found = True
        main_fields = parse_main_fields(udp_payload)
        tlvs = parse_tlv(udp_payload, 65)
        tlv_dict = {k: v for k, v in tlvs}
        output_rows = []
        idx = 1
        for name, *_ in MAIN_FIELDS:
            output_rows.append((idx, name, main_fields.get(name, "")))
            idx += 1
        for tlv_type, tlv_name in TLV_ORDER:
            key = f"0x{tlv_type:02x}({tlv_name})"
            val = tlv_dict.get(tlv_type, "")
            output_rows.append((idx, key, val))
            idx += 1
        print("-" * 60)
        print_aligned(output_rows)
        print("-" * 60)
    if not found:
        print("No matching UDP packets found (payload magic not matched).")

if __name__ == "__main__":
    main()