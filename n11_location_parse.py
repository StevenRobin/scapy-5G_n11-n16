from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder

# Custom HTTP/2 Frame Header Parser
class HTTP2FrameHeader(Packet):
    name = "HTTP2FrameHeader"
    fields_desc = [
        BitField("length", 0, 24),
        ByteField("type", 0),
        ByteField("flags", 0),
        BitField("reserved", 0, 1),
        BitField("stream_id", 0, 31)
    ]

def process_http2_frame_header(raw, offset):
    """Parse HTTP/2 frame header."""
    try:
        frame_header = HTTP2FrameHeader(raw[offset:offset + 9])
        frame_len = frame_header.length
        frame_type = frame_header.type
        frame_end = offset + 9 + frame_len
        frame_data = raw[offset + 9:frame_end]
        return frame_header, frame_len, frame_type, frame_data, frame_end
    except Exception as e:
        print(f"Frame parsing error: {str(e)}")
        return None, None, None, None, None

def extract_location_from_headers(headers_data):
    """Extract the 'location' field from HTTP/2 headers."""
    try:
        decoder = Decoder()
        headers = decoder.decode(headers_data)
        for name, value in headers:
            if name.lower() == "location":
                return value
    except Exception as e:
        print(f"Error decoding headers: {str(e)}")
    return None

def process_packet(pkt, packet_index, target_index):
    """Process the packet and extract 'location' field if it's the target."""
    if packet_index == target_index and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0

        while offset + 9 <= len(raw):
            # Parse frame header
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            # Process HEADERS frame (type 0x1)
            if frame_type == 0x1:
                location = extract_location_from_headers(frame_data)
                if location:
                    print(f"Extracted location: {location}")
                    return location

            # Move to the next frame
            offset = frame_end
    return None

# ---------------------- Main Script ----------------------
PCAP_IN = "pcap/N11_create_50p.pcap"  # Path to your PCAP file
TARGET_PACKET_INDEX = 46  # The target packet index (1-based)

print(f"Processing file: {PCAP_IN}")
packets = rdpcap(PCAP_IN)

if TARGET_PACKET_INDEX <= len(packets):
    target_packet = packets[TARGET_PACKET_INDEX - 1]  # 1-based index to 0-based
    location = process_packet(target_packet, TARGET_PACKET_INDEX, TARGET_PACKET_INDEX)
    if location:
        print(f"'location' field from packet {TARGET_PACKET_INDEX}: {location}")
    else:
        print(f"'location' field not found in packet {TARGET_PACKET_INDEX}.")
else:
    print(f"Packet {TARGET_PACKET_INDEX} does not exist in the provided PCAP file.")