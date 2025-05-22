#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
最简单的验证脚本 - 直接用字节形式查找关键字段
"""

from scapy.all import *
import sys

def main(pcap_file):
    """主函数"""
    print(f"读取PCAP文件: {pcap_file}")
    
    # 读取PCAP文件
    try:
        packets = rdpcap(pcap_file)
        print(f"读取了 {len(packets)} 个报文")
    except Exception as e:
        print(f"读取PCAP文件时出错: {e}")
        return
    
    # 确保有足够的报文
    if len(packets) < 15:
        print(f"PCAP文件中只有 {len(packets)} 个报文，不足15个")
        return
    
    # 获取第15个报文
    pkt15 = packets[14]
    
    # 将整个报文转换为字节
    pkt_bytes = bytes(pkt15)
      # 搜索关键字段
    server_smf = b'server: SMF' in pkt_bytes or b'Server: SMF' in pkt_bytes
    content_length = b'content-length:' in pkt_bytes or b'Content-Length:' in pkt_bytes
    content_length_351 = b'content-length: 351' in pkt_bytes or b'Content-Length: 351' in pkt_bytes
    
    print(f"'server: SMF'字段: {'存在' if server_smf else '不存在'}")
    print(f"'content-length'字段: {'存在' if content_length else '不存在'}")
    print(f"'content-length: 351'字段: {'存在' if content_length_351 else '不存在'}")
    
    # 第15个数据包应该有content-length: 351但不应该有server: SMF
    if not server_smf and content_length_351:
        print("√ 成功: 符合要求 - 包含content-length: 351，不包含server: SMF!")
    else:
        print("× 失败: 不符合要求!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    main(sys.argv[1])
