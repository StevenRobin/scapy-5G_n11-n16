#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import rdpcap, Raw
import binascii

# 读取PCAP文件
pcap_file = "pcap/N16_fixed_final.pcap"
packets = rdpcap(pcap_file)

with open('basic_output.txt', 'w') as f:
    f.write(f"PCAP包含 {len(packets)} 个报文\n")
    
    # 获取第15个报文（索引14）
    pkt15 = packets[14]
    
    if pkt15.haslayer(Raw):
        raw_data = bytes(pkt15[Raw].load)
        f.write(f"第15个报文负载长度: {len(raw_data)}字节\n")
        f.write(f"前100字节(hex): {binascii.hexlify(raw_data[:100]).decode()}\n")
        
        # 检查帧头
        if len(raw_data) >= 9:
            frame_length = int.from_bytes(raw_data[0:3], byteorder='big')
            frame_type = raw_data[3]
            f.write(f"\n第一个帧长度: {frame_length}, 类型: {frame_type}\n")
            
            # 检查是否包含content-length
            header_payload = raw_data[9:9+frame_length]
            if b'content-length' in header_payload:
                f.write("找到content-length文本\n")
            else:
                f.write("未找到content-length文本\n")
            
            # 直接输出可以人工阅读的文本部分
            visible_text = b''
            for byte in header_payload:
                if 32 <= byte <= 126:  # 可打印ASCII字符
                    visible_text += bytes([byte])
                else:
                    visible_text += b'.'
            
            f.write(f"可读文本: {visible_text.decode('ascii', errors='ignore')}\n")
            
            # 检查另一个帧是否是DATA帧
            if len(raw_data) >= 9 + frame_length + 9:
                offset = 9 + frame_length
                data_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
                data_type = raw_data[offset+3]
                f.write(f"\n第二个帧长度: {data_length}, 类型: {data_type}\n")
    else:
        f.write("第15个报文没有Raw层\n")

print("分析完成，结果保存在basic_output.txt中")
