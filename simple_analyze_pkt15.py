#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
简单直接地分析和显示第15个报文中的HTTP/2头部
"""

from scapy.all import rdpcap, Raw
import binascii
import sys

def main():
    pcap_file = "pcap/N16_fixed_final.pcap"
    
    print(f"读取PCAP文件: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    if len(packets) < 15:
        print(f"PCAP只包含 {len(packets)} 个报文，少于15个")
        return
    
    # 获取第15个报文（索引14）
    pkt15 = packets[14]
    
    if not pkt15.haslayer(Raw):
        print("第15个报文没有Raw层")
        return
    
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15个报文负载总长度: {len(raw_data)} 字节")
    
    # 解析HTTP/2帧
    offset = 0
    while offset < len(raw_data) - 9:  # 9字节是帧头长度
        if offset + 9 > len(raw_data):
            break
            
        try:
            frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            print(f"\n帧位置: {offset}")
            print(f"帧类型: {frame_type} ({['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS', 'PUSH_PROMISE', 'PING', 'GOAWAY', 'WINDOW_UPDATE', 'CONTINUATION'][frame_type] if frame_type < 10 else '未知'})")
            print(f"帧长度: {frame_length}")
            print(f"帧标志: {bin(flags)[2:].zfill(8)}")
            print(f"流ID: {stream_id}")
            
            if offset + 9 + frame_length > len(raw_data):
                print("警告: 帧长度超出负载范围")
                break
                
            frame_payload = raw_data[offset+9:offset+9+frame_length]
            
            # 打印帧载荷的十六进制表示
            hex_payload = binascii.hexlify(frame_payload).decode()
            print(f"帧载荷 (十六进制): {hex_payload}")
            
            # 对于HEADERS帧，尝试解析和显示其中的HTTP头部
            if frame_type == 0x1:  # HEADERS帧
                print("\n分析HEADERS帧内容:")
                
                # 检查是否包含常见的硬编码头部字段
                # ':status: 201'的常见HPACK表示
                if b'\x88\x40' in frame_payload:
                    print("发现:status: 201 (HPACK编码: 88 40)")
                    
                # 'content-length: 351'的可能表示
                if b'content-length: 351' in frame_payload:
                    print("发现content-length: 351 (直接文本)")
                    
                # content-length的HPACK编码可能形式
                cl_patterns = [
                    b'\x64\x23\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68\x3a\x20\x33\x35\x31',  # 可能的HPACK编码
                    b'\x3f\x64\x23\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68\x3a\x20\x33\x35\x31'  # 另一种可能形式
                ]
                
                for pattern in cl_patterns:
                    if pattern in frame_payload:
                        print(f"发现content-length: 351的可能HPACK编码: {binascii.hexlify(pattern).decode()}")
                
                # 检查:scheme: http字段
                if b':scheme: http' in frame_payload or b'\x86' in frame_payload:
                    print("发现:scheme: http字段 (可能是HPACK编码: 86)")
                
            offset += 9 + frame_length
        except Exception as e:
            print(f"解析帧错误: {e}")
            offset += 1

if __name__ == "__main__":
    main()
