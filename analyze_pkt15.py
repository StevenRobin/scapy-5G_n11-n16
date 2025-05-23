#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
分析第15个数据包中的HTTP/2头部
"""

from scapy.all import *
import binascii

def analyze_packet15(pcap_file):
    """详细分析第15个数据包"""
    print(f"读取PCAP文件: {pcap_file}")
    
    # 读取PCAP文件
    packets = rdpcap(pcap_file)
    print(f"读取了 {len(packets)} 个报文")
    
    # 获取第15个报文(索引为14)
    if len(packets) < 15:
        print(f"错误: PCAP文件中只有 {len(packets)} 个报文，不足15个")
        return
    
    pkt15 = packets[14]
    if not pkt15.haslayer(Raw):
        print("错误: 第15个报文没有原始数据负载")
        return
    
    # 获取原始数据
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15个报文原始数据长度: {len(raw_data)}")
    print(f"原始数据前50字节的十六进制表示: {raw_data[:50].hex()}")
    
    # 分析每个可能的HTTP/2帧
    offset = 0
    while offset < len(raw_data) - 9:  # 至少需要9字节的帧头
        try:
            frame_len = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            frame_flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            # 打印可能的帧信息
            print(f"\n在偏移量 {offset} 处找到可能的帧:")
            print(f"  帧长度: {frame_len}")
            print(f"  帧类型: {frame_type} ({get_frame_type_name(frame_type)})")
            print(f"  帧标志: {frame_flags:08b}")
            print(f"  流ID: {stream_id}")
            
            # 确认帧长度合理
            if 0 <= frame_len < 16384 and offset + 9 + frame_len <= len(raw_data):
                frame_data = raw_data[offset+9:offset+9+frame_len]
                print(f"  帧数据长度: {len(frame_data)}")
                print(f"  帧数据前20字节: {frame_data[:20].hex()}")
                
                # 如果是HEADERS帧(类型=1)，尝试解析头部
                if frame_type == 1:
                    print("  这是HEADERS帧，尝试解析HTTP/2头部:")
                    analyze_headers_frame(frame_data)
                
                # 检查是否包含特定字段
                if b"server: SMF" in frame_data or b"Server: SMF" in frame_data:
                    print("  ✓ 包含 'server: SMF' 字段")
                else:
                    print("  ✗ 不包含 'server: SMF' 字段")
                
                if b"content-length" in frame_data or b"Content-Length" in frame_data:
                    print("  ✓ 包含 'content-length' 字段")
                else:
                    print("  ✗ 不包含 'content-length' 字段")
                
                # 移动到下一个可能的帧
                offset += 9 + frame_len
            else:
                # 如果帧长度不合理，则移动一个字节
                offset += 1
        except Exception as e:
            print(f"  解析出错: {e}")
            offset += 1
    
    print("\n原始HTTP/2数据分析完成")

def get_frame_type_name(frame_type):
    """返回HTTP/2帧类型的名称"""
    frame_types = {
        0: "DATA",
        1: "HEADERS",
        2: "PRIORITY",
        3: "RST_STREAM",
        4: "SETTINGS",
        5: "PUSH_PROMISE",
        6: "PING",
        7: "GOAWAY",
        8: "WINDOW_UPDATE",
        9: "CONTINUATION"
    }
    return frame_types.get(frame_type, "UNKNOWN")

def analyze_headers_frame(frame_data):
    """尝试解析HEADERS帧中的HTTP/2头部"""
    # 检查是否有优先级标志(E标志)
    offset = 0
    if frame_data and len(frame_data) > 0 and (frame_data[0] & 0x20):
        # 跳过优先级信息(5字节)
        offset = 5
    
    # 尝试解析HPACK编码的头部(仅简单显示二进制数据)
    header_block = frame_data[offset:]
    print(f"    头部块长度: {len(header_block)}")
    print(f"    头部块数据: {header_block[:50].hex()}...")
    
    # 简单搜索常见的HTTP头部字段(二进制形式)
    common_headers = [
        b":status", b":path", b":method", b":scheme", b":authority",
        b"server", b"content-length", b"content-type", b"date"
    ]
    
    for header in common_headers:
        if header in header_block:
            print(f"    可能包含头部字段: {header.decode('utf-8', errors='replace')}")

if __name__ == "__main__":
    analyze_packet15("pcap/N16_1512.pcap")
