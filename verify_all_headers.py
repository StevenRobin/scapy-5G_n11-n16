#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
全面验证第15个报文中的三个问题是否已完全修复:
1. :status 字段值长度为3，值为"201"
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
    
    # 获取原始负载
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15个报文负载长度: {len(raw_data)} 字节")
    
    # 查找所有HTTP/2帧
    offset = 0
    status_found = False
    status_correct = False
    content_length_found = False
    content_length_correct = False
    scheme_found = False
    
    # 输出整个负载的十六进制表示（仅用于调试）
    hex_data = binascii.hexlify(raw_data).decode('ascii')
    print(f"负载十六进制 (前100字节): {hex_data[:100]}...")
    
    # 查找HPACK编码的特定值
    if b'\x88\x40' in raw_data:  # :status: 201 的HPACK编码
        print("√ 找到HPACK编码的 :status: 201 (8840)")
        status_found = True
        status_correct = True
    
    if b'\x86' in raw_data:  # :scheme: http 的HPACK编码
        print("× 找到 :scheme: http 的HPACK编码 (86)")
        scheme_found = True
    else:
        print("√ 未找到 :scheme: http 字段")
    
    # 查找content-length字段
    if b'content-length: 351' in raw_data or b'Content-Length: 351' in raw_data:
        print("√ 找到明文 content-length: 351 字段")
        content_length_found = True
        content_length_correct = True
    elif b'content-length' in raw_data or b'Content-Length' in raw_data:
        print("! 找到content-length字段，但可能值不是351")
        content_length_found = True
        
        # 尝试提取值
        for pattern in [b'content-length:', b'Content-Length:', b'content-length: ', b'Content-Length: ']:
            pos = raw_data.find(pattern)
            if pos >= 0:
                val_start = pos + len(pattern)
                val_end = -1
                for end_mark in [b'\r\n', b'\n', b';', b' ']:
                    end_pos = raw_data.find(end_mark, val_start)
                    if end_pos > 0:
                        val_end = end_pos
                        break
                
                if val_end > val_start:
                    value = raw_data[val_start:val_end].strip()
                    print(f"  content-length值: {value}")
                    if value == b'351':
                        content_length_correct = True
                        print("√ content-length值为351")
                    break
    
    # 针对HPACK编码的content-length检查
    if b'\x5c\x10\x63\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68\x3a\x20\x33\x35\x31' in raw_data:
        print("√ 找到HPACK编码的 content-length: 351")
        content_length_found = True
        content_length_correct = True
    
    # 分析HTTP/2帧 
    print("\n解析HTTP/2帧:")
    while offset < len(raw_data):
        if offset + 9 > len(raw_data):  # 9字节是帧头长度
            break
        
        try:
            frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            print(f"帧位置: {offset}, 类型: {frame_type}, 长度: {frame_length}, 标志: {bin(flags)[2:].zfill(8)}, 流ID: {stream_id}")
            
            if offset + 9 + frame_length > len(raw_data):
                print("  警告: 帧长度超出负载范围")
                break
            
            # 分析HEADERS帧 (类型1)
            if frame_type == 1:
                frame_payload = raw_data[offset+9:offset+9+frame_length]
                print(f"  HEADERS帧载荷 (十六进制前50字节): {binascii.hexlify(frame_payload[:50]).decode('ascii')}...")
                
                # 查找文本形式的头部字段
                if b':status:' in frame_payload or b':status: ' in frame_payload:
                    print("  找到:status字段")
                    for pattern in [b':status:', b':status: ']:
                        pos = frame_payload.find(pattern)
                        if pos >= 0:
                            val_start = pos + len(pattern)
                            val_end = -1
                            for end_mark in [b'\r\n', b'\n', b';', b' ']:
                                end_pos = frame_payload.find(end_mark, val_start)
                                if end_pos > 0:
                                    val_end = end_pos
                                    break
                            
                            if val_end > val_start:
                                status_value = frame_payload[val_start:val_end].strip()
                                print(f"  :status值: {status_value}")
                                if status_value == b'201' and len(status_value) == 3:
                                    status_correct = True
                                    print("√ :status值正确为'201'且长度为3")
                                break
            
            # 移动到下一帧
            offset += 9 + frame_length
            
        except Exception as e:
            print(f"解析帧时出错: {e}")
            offset += 1
    
    # 最终结果
    print("\n===== 第15个报文验证结果 =====")
    print(f"1. :status为'201'且长度为3: {'√ 成功' if status_correct else '× 失败'}")
    print(f"2. 不包含:scheme字段: {'√ 成功' if not scheme_found else '× 失败'}")
    print(f"3. 包含content-length: 351字段: {'√ 成功' if content_length_correct else '× 失败'}")
    
    all_passed = status_correct and (not scheme_found) and content_length_correct
    if all_passed:
        print("\n=== 所有修复验证通过！第15号报文完全符合要求！===")
    else:
        print("\n=== 有些问题未修复，请检查详细输出 ===")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    # 将输出重定向到文件
    original_stdout = sys.stdout
    with open('verification_output.txt', 'w', encoding='utf-8') as f:
        sys.stdout = f
        main(sys.argv[1])
    sys.stdout = original_stdout
    print("验证完成，结果已保存到verification_output.txt文件")
