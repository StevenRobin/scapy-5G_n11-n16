#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import rdpcap, Raw
import binascii

print("读取PCAP文件...")
pcap_file = "pcap/N16_fixed_final.pcap"
packets = rdpcap(pcap_file)

print(f"PCAP包含 {len(packets)} 个报文")

# 获取第15个报文（索引14）
pkt15 = packets[14]

if pkt15.haslayer(Raw):
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15个报文负载长度: {len(raw_data)} 字节")
    
    # 假设这是一个HTTP/2报文，寻找HEADERS帧
    # HTTP/2帧结构: Length(3字节) + Type(1字节) + Flags(1字节) + Reserved(1位) + Stream Identifier(31位) + Payload
    print("\n帧结构分析:")
    
    offset = 0
    # 解析第一个帧 - 应该是HEADERS帧
    if len(raw_data) >= 9:  # 至少需要9字节的帧头
        length = int.from_bytes(raw_data[0:3], byteorder='big')
        frame_type = raw_data[3]
        flags = raw_data[4]
        stream_id = int.from_bytes(raw_data[5:9], byteorder='big') & 0x7FFFFFFF
        
        print(f"帧头: {binascii.hexlify(raw_data[0:9]).decode()}")
        print(f"  长度: {length} 字节")
        print(f"  类型: {frame_type} ({['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS'][frame_type] if frame_type < 5 else '其他'})")
        print(f"  标志: {flags:08b}")
        print(f"  流ID: {stream_id}")
        
        if frame_type == 1 and offset + 9 + length <= len(raw_data):  # HEADERS帧
            headers_block = raw_data[9:9+length]
            print(f"\nHEADERS帧负载 ({length} 字节): {binascii.hexlify(headers_block).decode()}")
            
            # 检查是否包含某些关键字节序列
            print("\n关键字段检查:")
            
            # :status: 201 (HPACK索引表示可能是0x88 0x40)
            if b'\x88\x40' in headers_block:
                print("  找到可能的:status: 201 HPACK编码 (88 40)")
            
            # content-length: 351 (直接表示)
            if b'content-length: 351' in headers_block:
                print("  找到文本形式的'content-length: 351'")
            
            # content-length字段的可能HPACK表示
            cl_pattern = b'\x64\x23\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68'
            if cl_pattern in headers_block:
                pos = headers_block.find(cl_pattern)
                print(f"  找到可能的content-length HPACK编码在位置 {pos}: {binascii.hexlify(headers_block[pos:pos+20]).decode()}")
            
            # :scheme: http (HPACK索引表示可能是0x86)
            if b'\x86' in headers_block:
                print("  找到可能的:scheme: http HPACK编码 (86)")
            
            # 视图分析所有出现的冒号(":") - 这在HTTP/2伪头部字段中很重要
            print("\n分析伪头部字段:")
            text_headers = headers_block.decode('latin1', errors='ignore')
            for line in text_headers.split('\n'):
                if ':' in line and len(line) < 50:  # 防止输出过长的行
                    print(f"  {line}")
    
    # 尝试解析第二个帧 - 应该是DATA帧
    if len(raw_data) >= 9 + length + 9:
        offset = 9 + length
        data_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
        data_type = raw_data[offset+3]
        data_flags = raw_data[offset+4]
        data_stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
        
        print(f"\n第二个帧头: {binascii.hexlify(raw_data[offset:offset+9]).decode()}")
        print(f"  长度: {data_length} 字节")
        print(f"  类型: {data_type} ({['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS'][data_type] if data_type < 5 else '其他'})")
        print(f"  标志: {data_flags:08b}")
        print(f"  流ID: {data_stream_id}")
        
        if data_type == 0 and offset + 9 + data_length <= len(raw_data):  # DATA帧
            data_block = raw_data[offset+9:offset+9+data_length]
            print(f"\nDATA帧负载前50字节 (总长度 {data_length} 字节): {binascii.hexlify(data_block[:50]).decode()}")
            
            # 尝试以文本形式显示DATA帧内容
            try:
                data_text = data_block.decode('utf-8', errors='ignore')
                if len(data_text) > 100:
                    data_text = data_text[:100] + "..."
                print(f"\nDATA帧内容(UTF-8): {data_text}")
            except:
                pass
else:
    print("第15个报文没有Raw层")
