#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
最简单直接的脚本，分析并打印第15个报文的信息
"""

from scapy.all import rdpcap, Raw
import binascii

try:
    print("开始分析PCAP文件")
    
    # 读取PCAP文件
    pcap_file = "pcap/N16_fixed_final.pcap"
    packets = rdpcap(pcap_file)
    print(f"PCAP包含 {len(packets)} 个报文")
    
    # 获取第15个报文（索引14）
    pkt15 = packets[14]
    print("获取到第15个报文")
    
    if pkt15.haslayer(Raw):
        raw_data = bytes(pkt15[Raw].load)
        print(f"报文有Raw层，负载长度: {len(raw_data)}字节")
        
        # 解析HTTP/2帧
        if len(raw_data) >= 9:  # 至少有一个帧头
            frame_length = int.from_bytes(raw_data[0:3], byteorder='big')
            frame_type = raw_data[3]
            frame_flags = raw_data[4]
            frame_stream_id = int.from_bytes(raw_data[5:9], byteorder='big') & 0x7FFFFFFF
            
            print(f"第一个帧: 长度={frame_length}, 类型={frame_type}, 标志={frame_flags:08b}, 流ID={frame_stream_id}")
            
            if frame_type == 1:  # HEADERS帧
                print("这是一个HEADERS帧")
                
                # 检查HEADERS载荷
                if 9 + frame_length <= len(raw_data):
                    frame_payload = raw_data[9:9+frame_length]
                    print(f"HEADERS载荷长度: {len(frame_payload)}字节")
                    print(f"HEADERS载荷(hex): {binascii.hexlify(frame_payload).decode()}")
                    
                    # 查找content-length
                    if b'content-length' in frame_payload:
                        pos = frame_payload.find(b'content-length')
                        print(f"找到content-length在位置 {pos}")
                        # 显示上下文
                        context_start = max(0, pos - 5)
                        context_end = min(len(frame_payload), pos + 25)
                        context = frame_payload[context_start:context_end]
                        print(f"上下文: {context.decode('latin1', errors='ignore')}")
                    else:
                        print("未找到content-length文本")
            
            # 检查是否有第二个帧（应该是DATA帧）
            if 9 + frame_length + 9 <= len(raw_data):
                offset = 9 + frame_length
                data_frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
                data_frame_type = raw_data[offset+3]
                data_frame_flags = raw_data[offset+4]
                data_stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
                
                print(f"第二个帧: 长度={data_frame_length}, 类型={data_frame_type}, 标志={data_frame_flags:08b}, 流ID={data_stream_id}")
                
                if data_frame_type == 0:  # DATA帧
                    print("这是一个DATA帧")
    else:
        print("第15个报文没有Raw层")

except Exception as e:
    print(f"发生错误: {e}")
