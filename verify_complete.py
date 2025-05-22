#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
验证第15号报文是否满足所有要求的详细检查工具
"""

from scapy.all import *
import binascii
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
    
    if not pkt15.haslayer(Raw):
        print("第15个报文没有Raw层")
        return
    
    # 获取原始负载
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15个报文负载长度: {len(raw_data)} 字节")
    
    # 解析所有帧
    frames = []
    offset = 0
    
    while offset < len(raw_data):
        if offset + 9 > len(raw_data):
            break
            
        try:
            frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            frame_flags = raw_data[offset+4]
            # 获取流ID (31位) - 第一位是保留位
            reserved = (raw_data[offset+5] & 0x80) >> 7  # 最高位是保留位
            stream_id = ((raw_data[offset+5] & 0x7F) << 24) | (raw_data[offset+6] << 16) | (raw_data[offset+7] << 8) | raw_data[offset+8]
            
            # 帧类型名称
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
            frame_type_name = frame_types.get(frame_type, f"UNKNOWN({frame_type})")
            
            # HEADERS帧标志
            headers_flags = {
                0x01: "END_STREAM",
                0x04: "END_HEADERS",
                0x08: "PADDED",
                0x20: "PRIORITY"
            }
            
            # 提取帧内容
            frame_data = raw_data[offset+9:offset+9+frame_length]
            
            # 添加帧信息
            frames.append({
                "offset": offset,
                "length": frame_length,
                "type": frame_type,
                "type_name": frame_type_name,
                "flags": frame_flags,
                "flags_desc": ", ".join(name for flag, name in headers_flags.items() if frame_type == 1 and frame_flags & flag),
                "stream_id": stream_id,
                "data": frame_data,
                "end_offset": offset+9+frame_length
            })
            
            # 移动到下一个帧
            offset = offset+9+frame_length
        except Exception as e:
            print(f"解析帧出错 (位置 {offset}): {e}")
            offset += 1
    
    # 输出所有帧的概述
    print(f"\n找到 {len(frames)} 个HTTP/2帧:")
    for i, frame in enumerate(frames):
        flags_info = f" [{frame['flags_desc']}]" if frame['flags_desc'] else ""
        print(f"帧 {i+1}: {frame['type_name']} (长度={frame['length']}, 流ID={frame['stream_id']}{flags_info})")
    
    # 查找HEADERS帧
    headers_frame = None
    for frame in frames:
        if frame["type"] == 1:  # HEADERS
            headers_frame = frame
            break
    
    if headers_frame:
        print("\n=== HEADERS帧分析 ===")
        print(f"长度: {headers_frame['length']} 字节")
        print(f"流ID: {headers_frame['stream_id']}")
        print(f"标志: 0x{headers_frame['flags']:02X} {headers_frame['flags_desc']}")
        print("HEADERS内容 (十六进制):")
        hex_headers = binascii.hexlify(headers_frame['data']).decode()
        # 每行显示32个十六进制字符
        for i in range(0, len(hex_headers), 64):
            print(hex_headers[i:i+64])
        
        # 检查关键要求
        status_201 = b'\x88\x40' in headers_frame['data']
        scheme_http = b'\x86' in headers_frame['data']
        content_length_str = b'content-length: 351'
        content_length_hex = binascii.hexlify(content_length_str).decode()
        content_length = content_length_str.lower() in headers_frame['data'].lower() or content_length_hex.lower() in binascii.hexlify(headers_frame['data']).decode().lower()
        
        print("\n=== 关键要求检查 ===")
        print(f"1. :status: 201 (HPACK编码 8840): {'✓ 存在' if status_201 else '✗ 不存在'}")
        print(f"2. :scheme: http (HPACK编码 86): {'✗ 存在' if scheme_http else '✓ 不存在'}")
        print(f"3. content-length: 351: {'✓ 存在' if content_length else '✗ 不存在'}")
        
        # 总体评估
        if status_201 and not scheme_http and content_length:
            print("\n✅ 所有要求满足! 第15号报文已成功修复。")
        else:
            print("\n❌ 有些要求未满足，需要进一步修复。")
    else:
        print("\n未找到HEADERS帧!")
    
    # 查找DATA帧
    data_frame = None
    for frame in frames:
        if frame["type"] == 0:  # DATA
            data_frame = frame
            break
    
    if data_frame:
        print("\n=== DATA帧分析 ===")
        print(f"长度: {data_frame['length']} 字节")
        print(f"流ID: {data_frame['stream_id']}")
        try:
            # 尝试解码为文本
            data_text = data_frame['data'].decode('utf-8', errors='replace')
            print("DATA内容 (前100个字符):")
            print(data_text[:100], "..." if len(data_text) > 100 else "")
        except Exception as e:
            print(f"无法解码DATA内容为文本: {e}")
            print("DATA内容 (前50个字节, 十六进制):")
            print(binascii.hexlify(data_frame['data'][:50]).decode())
    else:
        print("\n未找到DATA帧!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    main(sys.argv[1])
