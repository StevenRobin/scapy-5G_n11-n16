import sys
import struct
import socket
import datetime
from scapy.all import rdpcap, UDP

# TLV类型与名称映射（可根据协议补充/修改）
TLV_NAMES = {
    0x01: "PDU_ACTION",
    0x02: "UP_F_TEID",
    0x03: "DL_F_TEID",
    0x04: "PDU_SESSION_ID",
    0x05: "REMOVE_F_TEIDs",
    0x06: "PDU_SESSION_TYPE",
    0x07: "DYNAMICIPv4",
    0x08: "DYNAMICIPv6",
    0x09: "SNSSAI_SST",
    0x0a: "SNSSAI_SD",
    0x0b: "DNN",
    0x0c: "UE_ACTION",
    0x0d: "H0_TYPE",
    0x0e: "SRC_IPV4_ADDR",
    0x0f: "SRC_IPV6_ADDR",
    0x10: "DST_IPV4_ADDR",
    0x11: "DST_IPV6_ADDR",
    0x12: "ISP_MARKED_TIME",
    0x13: "MAC",
}

def format_hex(val, width):
    if val is None:
        return "None"
    return f"{val:0{width}x}"

def format_capture_time(val):
    if val is None:
        return "None"
    seconds = val // 1_000_000
    useconds = val % 1_000_000
    t = datetime.datetime.utcfromtimestamp(seconds)
    t_str = t.strftime("%b %d, %Y %H:%M:%S")
    return f"{t_str}.{useconds:06d} UTC"

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
            res[name] = "None"
            continue
        if fmt.endswith('s'):
            res[name] = "0x" + payload[offset:offset+size].hex()
        elif name == "Capture_time":
            val = struct.unpack_from(fmt, payload, offset)[0]
            res[name] = format_capture_time(val)
        else:
            val = struct.unpack_from(fmt, payload, offset)[0]
            res[name] = "0x" + format_hex(val, hexw)
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
        key = f"0x{tlv_type:02x}({TLV_NAMES.get(tlv_type, '')})"
        # 智能类型解码
        if tlv_type in (0x02, 0x03):  # TEID(4字节)或更长
            val = tlv_value.hex()
        elif tlv_type in (0x07, 0x0e, 0x10) and tlv_len == 4:
            val = socket.inet_ntoa(tlv_value)
        elif tlv_type in (0x08, 0x0f, 0x11) and tlv_len == 16:
            val = ":".join([tlv_value[i:i+2].hex() for i in range(0, 16, 2)])
        elif tlv_type == 0x12 and tlv_len == 8:
            tval = struct.unpack(">Q", tlv_value)[0]
            val = format_capture_time(tval)
        elif tlv_type == 0x13 and tlv_len == 6:
            val = ":".join(f"{b:02x}" for b in tlv_value)
        elif tlv_type == 0x0b: # DNN
            try:
                val = tlv_value.decode(errors="replace")
            except:
                val = tlv_value.hex()
        else:
            val = tlv_value.hex()
        tlvs.append((key, val))
        offset += 2 + tlv_len
    return tlvs

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
        fields = parse_main_fields(udp_payload)
        tlvs = parse_tlv(udp_payload, 65)
        print("-" * 60)
        print("主字段：")
        for k, v in fields.items():
            print(f"{k} : {v}")
        print("TLV字段：")
        for k, v in tlvs:
            print(f"{k} : {v}")
        print("-" * 60)
    if not found:
        print("No matching UDP packets found (payload magic not matched).")

if __name__ == "__main__":
    main()