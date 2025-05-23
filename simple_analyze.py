#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
import os

def simple_analyze():
    pcap_file = "h:/pythonProject/study_01/scapy-5G_n11-n16/pcap/N16_1512.pcap"
    
    # 检查文件是否存在
    if not os.path.exists(pcap_file):
        print(f"找不到文件: {pcap_file}")
        # 尝试列出可用的PCAP文件
        pcap_dir = "pcap"
        if os.path.exists(pcap_dir):
            print(f"可用的PCAP文件:")
            for file in os.listdir(pcap_dir):
                if file.endswith(".pcap"):
                    print(f"  - {file}")
        return
    
    print(f"读取PCAP文件: {pcap_file}")
    
    try:
        # 读取PCAP文件
        packets = rdpcap(pcap_file)
        print(f"成功读取了 {len(packets)} 个数据包")
        
        # 检查第15个数据包
        if len(packets) >= 15:
            packet_15 = packets[14]
            print("\n第15个数据包信息:")
            print(f"包长度: {len(packet_15)}")
            
            # 检查是否有Raw层
            if Raw in packet_15:
                raw_data = bytes(packet_15[Raw])
                print(f"Raw数据长度: {len(raw_data)}")
                print(f"前100字节: {raw_data[:100].hex()}")
                
                # 直接查找特定字符串
                if b'SMF' in raw_data:
                    print("✓ 检测到 'SMF' 字符串")
                else:
                    print("✗ 未检测到 'SMF' 字符串")
                
                if b'server' in raw_data.lower():
                    print("✓ 检测到 'server' 字符串")
                else:
                    print("✗ 未检测到 'server' 字符串")
                
                if b'content-length' in raw_data.lower():
                    print("✓ 检测到 'content-length' 字符串")
                    # 提取content-length附近的数据
                    idx = raw_data.lower().find(b'content-length')
                    if idx > 0:
                        print(f"content-length附近数据: {raw_data[idx:idx+30]}")
                else:
                    print("✗ 未检测到 'content-length' 字符串")
                    
                # 打印几个十六进制形式的字符
                print("\n一些常见头部字段的十六进制表示:")
                print(f"'server' 的十六进制: {b'server'.hex()}")
                print(f"'SMF' 的十六进制: {b'SMF'.hex()}")
                print(f"'content-length' 的十六进制: {b'content-length'.hex()}")
                print(f"'351' 的十六进制: {b'351'.hex()}")
            else:
                print("✗ 数据包没有Raw层")
        else:
            print(f"✗ PCAP文件中没有15个数据包，只有 {len(packets)} 个")
    
    except Exception as e:
        print(f"分析时出错: {e}")

if __name__ == "__main__":
    simple_analyze()
