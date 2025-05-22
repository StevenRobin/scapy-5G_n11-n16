#!/usr/bin/env python
# coding: utf-8

import logging
import sys
from scapy.all import rdpcap, Raw
from scapy.layers.inet import TCP
from hpack import Decoder

# Configure logging to console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

def parse_http2_headers(packet_data):
    """Try to parse HTTP/2 headers"""
    try:
        # Check if this is an HTTP/2 HEADERS frame
        frame_length = int.from_bytes(packet_data[0:3], byteorder="big")
        frame_type = packet_data[3]
        
        if frame_type != 1:  # 1 represents HEADERS frame
            logger.warning(f"Not a HEADERS frame, but type {frame_type}")
            return None
        
        logger.info(f"Found HTTP/2 HEADERS frame, length: {frame_length}")
        
        # Skip the 9-byte frame header
        headers_block_fragment = packet_data[9:9+frame_length]
        
        # Try using HPACK decoding
        try:
            decoder = Decoder()
            headers = decoder.decode(headers_block_fragment)
            
            # Convert iterator to list so it can be used multiple times
            header_list = list(headers)
            header_count = len(header_list)
            
            logger.info(f"Successfully parsed HTTP/2 headers, found {header_count} fields")
            
            for i, (name, value) in enumerate(header_list):
                name_str = name.decode("utf-8", errors="ignore") if isinstance(name, bytes) else name
                value_str = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else value
                logger.info(f"  Header field #{i+1}: {name_str} = {value_str}")
            
            return header_list
        except Exception as e:
            logger.error(f"HPACK decoding failed: {e}")
            
            # Try binary search for key fields
            logger.info("Trying binary search for key fields")
            
            # Try to find :status field
            status_pattern = b":status"
            pos = headers_block_fragment.find(status_pattern)
            if pos >= 0:
                logger.info(f"Found :status field at position {pos}")
                # Try to extract value
                val_start = pos + len(status_pattern)
                val_end = -1
                for end_mark in [b"\r\n", b"\n", b";", b",", b":"]:
                    end_pos = headers_block_fragment.find(end_mark, val_start)
                    if end_pos > 0:
                        val_end = end_pos
                        break
                
                if val_end > val_start:
                    status_value = headers_block_fragment[val_start:val_end].strip()
                    logger.info(f"Status value: {status_value}")
            
            # Try to find location field
            location_pattern = b"location"
            pos = headers_block_fragment.find(location_pattern)
            if pos >= 0:
                logger.info(f"Found location field at position {pos}")
                # Try to extract value
                val_start = pos + len(location_pattern)
                val_end = -1
                for end_mark in [b"\r\n", b"\n", b";", b",", b":"]:
                    end_pos = headers_block_fragment.find(end_mark, val_start)
                    if end_pos > 0:
                        val_end = end_pos
                        break
                
                if val_end > val_start:
                    location_value = headers_block_fragment[val_start:val_end].strip()
                    logger.info(f"Location value: {location_value}")
            
            # Try to find content-type field
            content_type_pattern = b"content-type"
            pos = headers_block_fragment.find(content_type_pattern)
            if pos >= 0:
                logger.info(f"Found content-type field at position {pos}")
                # Try to extract value
                val_start = pos + len(content_type_pattern)
                val_end = -1
                for end_mark in [b"\r\n", b"\n", b";", b",", b":"]:
                    end_pos = headers_block_fragment.find(end_mark, val_start)
                    if end_pos > 0:
                        val_end = end_pos
                        break
                
                if val_end > val_start:
                    content_type_value = headers_block_fragment[val_start:val_end].strip()
                    logger.info(f"Content-Type value: {content_type_value}")
            
            return None
    except Exception as e:
        logger.error(f"Error parsing HTTP/2 headers: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def main():
    # Load PCAP file
    pcap_path = "pcap/N16_1507.pcap"
    print(f"Loading PCAP file: {pcap_path}")
    logger.info(f"Loading PCAP file: {pcap_path}")
    
    try:
        packets = rdpcap(pcap_path)
        logger.info(f"Successfully loaded PCAP file, {len(packets)} packets total")
        
        # Get packet #15 (index 14)
        if len(packets) >= 15:
            pkt15 = packets[14]
            logger.info(f"Processing packet #15")
            
            # Check if it contains TCP payload
            if TCP in pkt15 and Raw in pkt15[TCP]:
                raw_data = pkt15[TCP].payload.load
                logger.info(f"Packet #15 contains {len(raw_data)} bytes of TCP payload")
                
                # Parse HTTP/2 headers
                headers = parse_http2_headers(raw_data)
                
                if headers:
                    logger.info("Successfully parsed HTTP/2 headers in packet #15")
                    
                    # Check if it contains the expected key fields
                    has_status = False
                    has_location = False
                    has_content_type = False
                    
                    for name, value in headers:
                        name_str = name.decode("utf-8", errors="ignore").lower() if isinstance(name, bytes) else name.lower()
                        
                        if name_str == ":status":
                            has_status = True
                            logger.info(f"Found Status field: {value}")
                        elif name_str == "location":
                            has_location = True
                            logger.info(f"Found Location field: {value}")
                        elif name_str == "content-type":
                            has_content_type = True
                            logger.info(f"Found Content-Type field: {value}")
                    
                    # Summary
                    if has_status and has_location and has_content_type:
                        logger.info("Packet #15 contains all necessary header fields! Fix successful!")
                    else:
                        missing = []
                        if not has_status:
                            missing.append("Status")
                        if not has_location:
                            missing.append("Location")
                        if not has_content_type:
                            missing.append("Content-Type")
                        
                        logger.warning(f"Packet #15 still missing these header fields: {', '.join(missing)}")
                else:
                    logger.warning("Unable to fully parse HTTP/2 headers in packet #15")
            else:
                logger.warning("Packet #15 doesn't contain TCP payload")
        else:
            logger.warning(f"Not enough packets in PCAP file, only {len(packets)} available")
    except Exception as e:
        logger.error(f"Error processing PCAP file: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()
