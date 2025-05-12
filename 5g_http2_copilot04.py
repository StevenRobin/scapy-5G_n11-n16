from scapy.all import *
from scapy.packet import Packet
from scapy.fields import BitField, ByteField
from hpack import Decoder, Encoder  # Import both Decoder and Encoder
import re

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

def modify_location_field(headers_data, new_supi):
    """Modify the SUPI part of the location value."""
    try:
        decoder = Decoder()
        headers = decoder.decode(headers_data)
        updated_headers = []

        for name, value in headers:
            if name.lower() == "location":
                print(f"Original location: {value}")
                # Replace SUPI in the location
                updated_value = re.sub(r"imsi-\d+", new_supi, value)
                print(f"Updated location: {updated_value}")
                updated_headers.append((name, updated_value))
            else:
                updated_headers.append((name, value))

        # Use Encoder to re-encode the modified headers
        encoder = Encoder()
        encoded_headers = encoder.encode(updated_headers)
        return encoded_headers

    except Exception as e:
        print(f"Error modifying location field: {str(e)}")
    return headers_data

def process_packet(pkt, packet_index, target_index, new_supi):
    """Process the packet and modify 'location' field if it's the target."""
    if packet_index == target_index and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        offset = 0

        modified_payload = bytearray(raw)

        while offset + 9 <= len(raw):
            # Parse frame header
            frame_header, frame_len, frame_type, frame_data, frame_end = process_http2_frame_header(raw, offset)
            if not frame_header:
                break

            # Process HEADERS frame (type 0x1)
            if frame_type == 0x1:
                modified_headers = modify_location_field(frame_data, new_supi)
                # Replace the original frame data with modified headers
                modified_payload[offset + 9:frame_end] = modified_headers

            # Move to the next frame
            offset = frame_end

        # Update the packet payload
        pkt[Raw].load = bytes(modified_payload)
    return pkt

# ---------------------- Main Script ----------------------
PCAP_IN = "pcap/N11_create_50p.pcap"  # Input PCAP file path
PCAP_OUT = "pcap/N11_modified.pcap"  # Output PCAP file path
TARGET_PACKET_INDEX = 46  # The target packet index (1-based)
NEW_SUPI = "imsi-460030100000022"  # New SUPI value

print(f"Processing file: {PCAP_IN}")
packets = rdpcap(PCAP_IN)

# Create a new list to hold modified packets
modified_packets = []

for index, pkt in enumerate(packets, start=1):
    modified_packet = process_packet(pkt, index, TARGET_PACKET_INDEX, NEW_SUPI)
    modified_packets.append(modified_packet)

# Write the modified packets to a new file
wrpcap(PCAP_OUT, modified_packets)
print(f"Modified PCAP saved to: {PCAP_OUT}")