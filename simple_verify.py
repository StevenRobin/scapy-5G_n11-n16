#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
简单验证第15号报文是否同时包含server:SMF和content-length字段
"""

from scapy.all import rdpcap
from scapy.layers.inet import Raw, TCP, IP
import sys
import os

def verify_fields(pcap_file):
    """验证第15号报文中的字段"""
    print(f"读取PCAP文件: {pcap_file}")
    
    # 读取PCAP文件
    packets = rdpcap(pcap_file)
    print(f"总共读取了 {len(packets)} 个报文")
    
    # 获取第15号报文（索引为14）
    if len(packets) < 15:
        print(f"错误: PCAP文件中只有 {len(packets)} 个报文，不足15个")
        return False
      # 提取第15号报文的原始负载
    pkt15 = packets[14]
    from scapy.layers.inet import Raw
    if not pkt15.haslayer(Raw):
        print("错误: 第15号报文没有Raw层")
        return False
    
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15号报文原始负载长度: {len(raw_data)} 字节")
    
    # 转换为ASCII友好的形式
    ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_data)
    
    # 检查字段
    server_smf = "server: SMF" in ascii_data or "Server: SMF" in ascii_data
    content_length = "content-length: " in ascii_data or "Content-Length: " in ascii_data
    
    print(f"'server: SMF'字段: {'存在' if server_smf else '不存在'}")
    print(f"'content-length'字段: {'存在' if content_length else '不存在'}")
    
    if server_smf and content_length:
        print("√ 成功: 两个字段都存在!")
        return True
    else:
        print("× 失败: 有字段缺失!")
        return False

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(f"错误: 文件 '{pcap_file}' 不存在")
        sys.exit(1)
    
    verify_fields(pcap_file)

if __name__ == "__main__":
    main()
