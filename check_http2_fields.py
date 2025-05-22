#!/usr/bin/env python
# coding: utf-8

from scapy.all import rdpcap, Raw
from scapy.layers.inet import TCP
import binascii

# 加载PCAP文件
pcap_path = "pcap/N16_1507.pcap"
print(f"Loading PCAP file: {pcap_path}")

packets = rdpcap(pcap_path)
print(f"Successfully loaded PCAP file, {len(packets)} packets total")

# 获取第15个报文 (索引14)
pkt15 = packets[14]
print(f"Processing packet #15")

# 检查是否包含TCP负载
if TCP in pkt15 and Raw in pkt15[TCP]:
    raw_data = pkt15[TCP].payload.load
    print(f"Packet #15 contains {len(raw_data)} bytes of TCP payload")
    
    # 提取HTTP/2帧信息
    frame_length = int.from_bytes(raw_data[0:3], byteorder="big")
    frame_type = raw_data[3]
    frame_flags = raw_data[4]
    stream_id = int.from_bytes(raw_data[5:9], byteorder="big")
    
    print(f"HTTP/2 Frame: type={frame_type}, length={frame_length}, flags={frame_flags:#x}, stream_id={stream_id}")
    
    # 如果是HEADERS帧，展示所有二进制数据
    if frame_type == 1:  # HEADERS帧
        print("This is a HEADERS frame, showing header block fragment:")
        headers_block = raw_data[9:9+frame_length]
        print(f"Header block length: {len(headers_block)} bytes")
        print("Header block hex dump:")
        print(binascii.hexlify(headers_block))
        
        # 尝试搜索关键字段
        print("\nSearching for key HTTP/2 fields in binary data:")
        
        # 查找:status字段
        status_pos = headers_block.find(b':status')
        if status_pos >= 0:
            print(f"Found :status field at position {status_pos}")
            # 尝试提取值
            end_pos = -1
            for marker in [b'\r', b'\n', b';', b',']:
                pos = headers_block.find(marker, status_pos)
                if pos > 0 and (end_pos < 0 or pos < end_pos):
                    end_pos = pos
            if end_pos > status_pos:
                value = headers_block[status_pos:end_pos]
                print(f"  Raw status field: {value}")
        
        # 查找location字段
        loc_pos = headers_block.find(b'location')
        if loc_pos >= 0:
            print(f"Found location field at position {loc_pos}")
            # 尝试提取值
            end_pos = -1
            for marker in [b'\r', b'\n', b';', b',']:
                pos = headers_block.find(marker, loc_pos)
                if pos > 0 and (end_pos < 0 or pos < end_pos):
                    end_pos = pos
            if end_pos > loc_pos:
                value = headers_block[loc_pos:end_pos]
                print(f"  Raw location field: {value}")
        
        # 查找content-type字段
        ct_pos = headers_block.find(b'content-type')
        if ct_pos >= 0:
            print(f"Found content-type field at position {ct_pos}")
            # 尝试提取值
            end_pos = -1
            for marker in [b'\r', b'\n', b';', b',']:
                pos = headers_block.find(marker, ct_pos)
                if pos > 0 and (end_pos < 0 or pos < end_pos):
                    end_pos = pos
            if end_pos > ct_pos:
                value = headers_block[ct_pos:end_pos]
                print(f"  Raw content-type field: {value}")
        
        # 查找原始HTTP/2头部字符串
        raw_strings = [
            b':status', b'201', b'Created',
            b'location', b'http', b'40.0.0.1', b'pdu-sessions',
            b'content-type', b'application/json'
        ]
        
        print("\nSearching for raw header strings:")
        for s in raw_strings:
            pos = headers_block.find(s)
            if pos >= 0:
                print(f"  Found '{s}' at position {pos}")
            else:
                print(f"  String '{s}' not found")
else:
    print("Packet #15 doesn't contain TCP payload")
