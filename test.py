import pyshark
from hpack.hpack import Decoder


def parse_pcap_for_supi(pcap_file):
    # Initialize the decoder
    decoder = Decoder()

    # Open the pcap file using pyshark
    cap = pyshark.FileCapture(pcap_file)

    # Iterate through packets
    for packet in cap:
        try:
            # Check if the packet contains HTTP/2
            if 'HTTP2' in packet:
                # Access the raw HTTP/2 headers
                http2_headers = bytes.fromhex(packet.http2.get('header'))  # Assuming pyshark parses headers as hex
                decoded_headers = decoder.decode(http2_headers)

                # Check if any key matches 'supi'
                for key, value in decoded_headers.items():
                    if key == 'supi':
                        print(f"Packet Number: {packet.number}, SUPI Found: {value}")
                        break
        except Exception as e:
            # Handle exceptions for malformed packets or unexpected structures
            print(f"Error processing packet {packet.number}: {e}")


if __name__ == "__main__":
    # Replace with your PCAP file path
    pcap_file = 'pcap/N11_create_50p.pcap'
    parse_pcap_for_supi(pcap_file)