#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
采用最简单的方式直接分析第15个报文的HPACK编码内容
"""

from scapy.all import rdpcap, Raw
import binascii
import re

def main():
    # 读取修复后的PCAP
    pcap_file = "pcap/N16_fixed_final.pcap"
    packets = rdpcap(pcap_file)
    
    # 获取第15个报文（索引14）
    pkt15 = packets[14]
    
    if not pkt15.haslayer(Raw):
        print("第15个报文没有Raw层")
        return
    
    # 获取原始负载
    raw_data = bytes(pkt15[Raw].load)
    
    # 打印整个原始负载的十六进制表示
    print(f"第15个报文负载长度: {len(raw_data)}字节")
    print(f"完整负载(hex): {binascii.hexlify(raw_data).decode()}")
    
    # 直接检查硬编码部分是否正确
    hardcoded_part = bytes.fromhex(
        "88407654c1488619d29aee30c08775c95a9f96d84f420a7adca8eb703d3f5a39349eb64d"
        "45f6423636f6e74656e742d6c656e6774683a203335316461746557363d9d96d84f420a7a"
        "dca8eb703d349eb64d45f6423636f6e74656e742d747970653a206170706c69636174696f"
        "6e2f6a736f6e"
    )
    
    # 检查这段硬编码是否存在于负载中
    if hardcoded_part in raw_data:
        print("\n已找到预期的HPACK编码头部")
        start_pos = raw_data.find(hardcoded_part)
        print(f"起始位置: {start_pos}")
        
        # 将HPACK中可见的文本部分提取出来
        text_parts = re.findall(rb'[\x20-\x7E]{3,}', hardcoded_part)
        print("\n可见文本部分:")
        for text in text_parts:
            print(f"  {text.decode()}")
    else:
        print("\n未找到预期的HPACK编码头部")
    
    # 特别检查content-length部分
    cl_pattern = b'content-length: 351'
    if cl_pattern in raw_data:
        print(f"\n直接找到文本 'content-length: 351'")
        pos = raw_data.find(cl_pattern)
        print(f"位置: {pos}")
    else:
        print("\n未直接找到文本 'content-length: 351'")
        
        # 检查是否有字符串形式的content-length
        cl_text = b'content-length'
        if cl_text in raw_data:
            pos = raw_data.find(cl_text)
            print(f"找到'content-length'文本在位置: {pos}")
            # 显示周围上下文
            start = max(0, pos - 5)
            end = min(len(raw_data), pos + 25)
            context = raw_data[start:end]
            print(f"上下文: {context.decode('latin1', errors='ignore')}")
            print(f"上下文(hex): {binascii.hexlify(context).decode()}")
        
        # 检查scheme部分
        scheme_pattern = b':scheme:'
        if scheme_pattern in raw_data:
            print(f"\n找到':scheme:'文本")
            pos = raw_data.find(scheme_pattern)
            print(f"位置: {pos}")
            # 显示周围上下文
            start = max(0, pos - 5)
            end = min(len(raw_data), pos + 15)
            context = raw_data[start:end]
            print(f"上下文: {context.decode('latin1', errors='ignore')}")
            print(f"上下文(hex): {binascii.hexlify(context).decode()}")
        else:
            print("\n未找到':scheme:'文本")
            
            # 检查是否有HPACK索引形式的scheme (0x86是scheme: http的索引表示)
            if b'\x86' in raw_data:
                pos = raw_data.find(b'\x86')
                print(f"找到可能的':scheme: http' HPACK索引(0x86)在位置: {pos}")
                start = max(0, pos - 5)
                end = min(len(raw_data), pos + 5)
                context = raw_data[start:end]
                print(f"上下文(hex): {binascii.hexlify(context).decode()}")

if __name__ == "__main__":
    main()
