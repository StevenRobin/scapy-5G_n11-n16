#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
直接在终端输出第15个报文的分析结果
"""

from scapy.all import rdpcap, Raw
import binascii
import re
import sys

# 读取PCAP文件
try:
    pcap_file = "pcap/N16_fixed_final.pcap"
    packets = rdpcap(pcap_file)
    
    print(f"PCAP包含 {len(packets)} 个报文")
    
    # 获取第15个报文（索引14）
    pkt15 = packets[14]
    
    if pkt15.haslayer(Raw):
        raw_data = bytes(pkt15[Raw].load)
        print(f"第15个报文负载长度: {len(raw_data)} 字节")
        
        # 提取第一个帧（应该是HEADERS帧）
        if len(raw_data) >= 9:
            frame_length = int.from_bytes(raw_data[0:3], byteorder='big')
            frame_type = raw_data[3]
            print(f"第一个帧: 长度={frame_length}, 类型={frame_type}")
            
            if frame_type == 1:  # HEADERS帧
                print("这是一个HEADERS帧")
                
                # 提取HEADERS帧负载
                headers_payload = raw_data[9:9+frame_length]
                print(f"HEADERS帧十六进制表示: {binascii.hexlify(headers_payload).decode()}")
                
                # 查找可读文本
                printable_pattern = re.compile(b'[\\x20-\\x7E]{4,}')
                printable_chunks = printable_pattern.findall(headers_payload)
                if printable_chunks:
                    print("\n可读文本块:")
                    for chunk in printable_chunks:
                        print(f"  {chunk.decode()}")
                
                # 检查是否包含"content-length: 351"
                cl_pattern = b'content-length: 351'
                if cl_pattern in headers_payload:
                    print("\n找到content-length: 351")
                else:
                    print("\n未找到完整的content-length: 351字符串")
                    
                    # 检查部分匹配
                    if b'content-length' in headers_payload:
                        print("找到content-length")
                        pos = headers_payload.find(b'content-length')
                        print(f"位置: {pos}")
                    if b'content-length:' in headers_payload:
                        print("找到content-length:")
                        pos = headers_payload.find(b'content-length:')
                        print(f"位置: {pos}")
                    if b': 351' in headers_payload:
                        print("找到: 351")
                        pos = headers_payload.find(b': 351')
                        print(f"位置: {pos}")
            
            # 检查第二个帧（应该是DATA帧）
            if len(raw_data) >= 9 + frame_length + 9:
                offset = 9 + frame_length
                data_frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
                data_frame_type = raw_data[offset+3]
                print(f"\n第二个帧: 长度={data_frame_length}, 类型={data_frame_type}")
                
                if data_frame_type == 0:  # DATA帧
                    print("这是一个DATA帧")
    else:
        print("第15个报文没有Raw层")
except Exception as e:
    print(f"错误: {e}")
