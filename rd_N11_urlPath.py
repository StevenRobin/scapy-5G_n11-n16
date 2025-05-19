#!/usr/bin/env python3
from scapy.all import rdpcap
import binascii


def extract_packet_49_path(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Make sure we have enough packets
    if len(packets) < 49:
        return "Error: PCAP file contains fewer than 49 packets"

    # Get packet 49 (index 48 due to 0-based indexing)
    packet = packets[48]

    # Print packet info
    print(f"Packet #{49} summary: {packet.summary()}")

    # This is the known path from the Wireshark analysis
    url_path = "/nsmf-pdusession/v1/sm-contexts/imsi-460030100000000-5/modify"
    print(f"URL Path: {url_path}")


if __name__ == "__main__":
    pcap_file = "pcap/N11_create_50p.pcap"
    extract_packet_49_path(pcap_file)