#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import rdpcap, Raw
import binascii

# 打开文件准备写入
with open('analyze_pkt15_output.txt', 'w') as outfile:
    def write(line):
        print(line)
        outfile.write(line + '\n')

    write("读取PCAP文件...")
    pcap_file = "pcap/N16_fixed_final.pcap"
    packets = rdpcap(pcap_file)

    write(f"PCAP包含 {len(packets)} 个报文")

    # 获取第15个报文（索引14）
    pkt15 = packets[14]

    if pkt15.haslayer(Raw):
        raw_data = bytes(pkt15[Raw].load)
        write(f"第15个报文负载长度: {len(raw_data)} 字节")
        write(f"负载十六进制: {binascii.hexlify(raw_data).decode()}")
        
        # 假设这是一个HTTP/2报文，寻找HEADERS帧
        write("\n帧结构分析:")
        
        offset = 0
        # 解析第一个帧 - 应该是HEADERS帧
        if len(raw_data) >= 9:  # 至少需要9字节的帧头
            length = int.from_bytes(raw_data[0:3], byteorder='big')
            frame_type = raw_data[3]
            flags = raw_data[4]
            stream_id = int.from_bytes(raw_data[5:9], byteorder='big') & 0x7FFFFFFF
            
            write(f"帧头: {binascii.hexlify(raw_data[0:9]).decode()}")
            write(f"  长度: {length} 字节")
            write(f"  类型: {frame_type} ({['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS'][frame_type] if frame_type < 5 else '其他'})")
            write(f"  标志: {flags:08b}")
            write(f"  流ID: {stream_id}")
            
            if frame_type == 1 and offset + 9 + length <= len(raw_data):  # HEADERS帧
                headers_block = raw_data[9:9+length]
                write(f"\nHEADERS帧负载 ({length} 字节): {binascii.hexlify(headers_block).decode()}")
                
                # 检查是否包含某些关键字节序列
                write("\n关键字段检查:")
                
                # :status: 201 (HPACK索引表示可能是0x88 0x40)
                if b'\x88\x40' in headers_block:
                    write("  找到可能的:status: 201 HPACK编码 (88 40)")
                
                # content-length: 351 (直接表示)
                if b'content-length: 351' in headers_block:
                    write("  找到文本形式的'content-length: 351'")
                
                # content-length字段的可能HPACK表示
                if b'content-length' in headers_block:
                    pos = headers_block.find(b'content-length')
                    write(f"  找到content-length文本在位置 {pos}")
                    context = headers_block[pos:pos+30]
                    write(f"  上下文: {binascii.hexlify(context).decode()}")
                    write(f"  文本: {context.decode('latin1', errors='ignore')}")
                
                # :scheme: http (HPACK索引表示可能是0x86)
                if b'\x86' in headers_block:
                    write("  找到可能的:scheme: http HPACK编码 (86)")
        
        # 尝试解析第二个帧 - 应该是DATA帧
        if len(raw_data) >= 9 + length + 9:
            offset = 9 + length
            data_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            data_type = raw_data[offset+3]
            data_flags = raw_data[offset+4]
            data_stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            write(f"\n第二个帧头: {binascii.hexlify(raw_data[offset:offset+9]).decode()}")
            write(f"  长度: {data_length} 字节")
            write(f"  类型: {data_type} ({['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS'][data_type] if data_type < 5 else '其他'})")
            write(f"  标志: {data_flags:08b}")
            write(f"  流ID: {data_stream_id}")
    else:
        write("第15个报文没有Raw层")
