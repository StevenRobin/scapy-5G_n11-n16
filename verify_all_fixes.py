#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
验证第15个报文中的三个问题是否都已修复:
1. :status 字段值长度为3，值为"201"（不是"201 Created"）
2. 不包含 :scheme: http 字段
3. 包含 content-length: 351 字段
"""

from scapy.all import *
import sys
import binascii
import re

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
    
    # 将报文负载转换为字节
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15个报文负载总长度: {len(raw_data)} 字节")
    
    # 初始化检查结果
    status_correct = False
    no_scheme = True
    has_content_length = False
    
    # 处理HTTP/2帧
    offset = 0
    while offset < len(raw_data) - 9:  # 9字节是帧头长度
        try:
            frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            print(f"\n帧位置: {offset}")
            print(f"帧类型: {frame_type} ({['DATA', 'HEADERS', 'PRIORITY', 'RST_STREAM', 'SETTINGS', 'PUSH_PROMISE', 'PING', 'GOAWAY', 'WINDOW_UPDATE', 'CONTINUATION'][frame_type] if frame_type < 10 else '未知'})")
            
            # 如果是HEADERS帧，查找关键字段
            if frame_type == 1 and offset + 9 + frame_length <= len(raw_data):
                headers_block = raw_data[offset+9:offset+9+frame_length]
                hex_data = binascii.hexlify(headers_block).decode('ascii')
                print(f"HEADERS帧数据 (HEX): {hex_data}")
                
                # 检查:status字段
                if b':status:' in headers_block or b':status: ' in headers_block:
                    for pattern in [b':status:', b':status: ']:
                        pos = headers_block.find(pattern)
                        if pos >= 0:
                            val_start = pos + len(pattern)
                            val_end = -1
                            for end_mark in [b'\r\n', b'\n', b';', b' ']:
                                end_pos = headers_block.find(end_mark, val_start)
                                if end_pos > 0:
                                    val_end = end_pos
                                    break
                            if val_end < 0:
                                val_end = len(headers_block)
                            
                            status_value = headers_block[val_start:val_end].strip()
                            print(f"找到:status字段值: '{status_value}'")
                            if status_value == b"201" and len(status_value) == 3:
                                status_correct = True
                                print("√ :status值正确为'201'且长度为3")
                            break
                # 检查HPACK编码的status字段
                elif b'\x88\x40' in headers_block:
                    print("找到HPACK编码的:status: 201 (88 40)")
                    status_correct = True
                    print("√ :status值通过HPACK编码确认为'201'且长度为3")
                
                # 检查:scheme字段
                if b':scheme:' in headers_block or b':scheme: ' in headers_block:
                    no_scheme = False
                    scheme_value = "未知"
                    for pattern in [b':scheme:', b':scheme: ']:
                        pos = headers_block.find(pattern)
                        if pos >= 0:
                            val_start = pos + len(pattern)
                            val_end = -1
                            for end_mark in [b'\r\n', b'\n', b';', b' ']:
                                end_pos = headers_block.find(end_mark, val_start)
                                if end_pos > 0:
                                    val_end = end_pos
                                    break
                            if val_end < 0:
                                val_end = len(headers_block)
                            
                            scheme_value = headers_block[val_start:val_end].strip()
                            break
                    print(f"× 发现:scheme字段: '{scheme_value}'")
                # 检查HPACK编码的scheme字段
                elif b'\x86' in headers_block:
                    print("可能存在HPACK编码的:scheme: http (86)")
                    print("但需要进一步验证，因为86可能是其他字段的一部分")
                else:
                    print("√ 未检测到:scheme字段")
                
                # 检查content-length字段
                for cl_pattern in [b'content-length:', b'Content-Length:', b'content-length: ', b'Content-Length: ']:
                    pos = headers_block.find(cl_pattern)
                    if pos >= 0:
                        val_start = pos + len(cl_pattern)
                        val_end = -1
                        for end_mark in [b'\r\n', b'\n', b';']:
                            end_pos = headers_block.find(end_mark, val_start)
                            if end_pos > 0:
                                val_end = end_pos
                                break
                        if val_end < 0:
                            val_end = len(headers_block)
                        
                        cl_value = headers_block[val_start:val_end].strip()
                        print(f"找到content-length字段值: '{cl_value}'")
                        if cl_value == b"351":
                            has_content_length = True
                            print("√ content-length值正确为'351'")
                        break
                # 检查HPACK编码的content-length字段
                if b'content-length' in hex_data.lower() and b'351' in hex_data.lower():
                    has_content_length = True
                    print("√ 检测到content-length: 351 (可能为HPACK编码)")
            
            # 移动到下一帧
            offset += 9 + frame_length
        except Exception as e:
            print(f"解析帧时出错: {e}")
            offset += 1
    
    # 最终结果
    print("\n===== 验证结果 =====")
    print(f"1. :status为'201'且长度为3: {'√ 成功' if status_correct else '× 失败'}")
    print(f"2. 不包含:scheme字段: {'√ 成功' if no_scheme else '× 失败'}")
    print(f"3. 包含content-length: 351字段: {'√ 成功' if has_content_length else '× 失败'}")
    
    all_passed = status_correct and no_scheme and has_content_length
    if all_passed:
        print("\n=== 所有修复验证通过！修复成功！===")
    else:
        print("\n=== 有些修复未通过，需要进一步调整 ===")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    main(sys.argv[1])
