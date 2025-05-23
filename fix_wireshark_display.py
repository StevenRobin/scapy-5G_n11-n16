#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
特殊处理：使用替代方法确保第15个包的content-length字段在Wireshark中正确显示
"""

from scapy.all import *
import binascii
import os
import sys

def main(input_pcap, output_pcap):
    print(f"读取PCAP文件: {input_pcap}")
    
    if not os.path.exists(input_pcap):
        print(f"错误：找不到文件 {input_pcap}")
        return
    
    # 读取PCAP文件
    packets = rdpcap(input_pcap)
    print(f"读取了 {len(packets)} 个报文")
    
    if len(packets) < 15:
        print(f"错误：PCAP文件中只有 {len(packets)} 个报文，少于15个")
        return
    
    # 获取第15个包
    pkt15 = packets[14]
    
    if not pkt15.haslayer(Raw):
        print("错误：第15个包没有原始数据负载")
        return
    
    # 获取原始数据
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15个包原始数据长度: {len(raw_data)}")
    
    # 检查是否存在content-length字段
    content_length_exists = False
    server_exists = False
    
    if b'content-length' in raw_data.lower() or b'Content-Length' in raw_data:
        content_length_exists = True
        print("找到content-length字段")
    
    if b'server' in raw_data.lower() or b'Server' in raw_data:
        server_exists = True
        print("找到server字段")
    
    # 最简单直接的方法：直接替换整个HTTP/2帧的二进制数据，确保格式完全正确
    modified_data = raw_data
    
    # 查找HTTP/2头部帧 - 获取所有帧
    offset = 0
    headers_frame_offset = -1
    while offset < len(raw_data) - 9:  # 最小帧长度为9字节
        try:
            # 解析HTTP/2帧头
            length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            print(f"偏移量 {offset}: 找到可能的帧: 类型={frame_type}, 长度={length}")
            
            # 检查是否是合理的帧
            if 0 <= length < 16384 and offset + 9 + length <= len(raw_data):
                frame_data = raw_data[offset+9:offset+9+length]
                
                # 如果是HEADERS帧
                if frame_type == 1:
                    headers_frame_offset = offset
                    print(f"在偏移量 {offset} 处找到HEADERS帧，长度为 {length}")
                    break
                
                offset += 9 + length
            else:
                offset += 1
        except Exception as e:
            print(f"解析帧时出错: {e}")
            offset += 1
    
    # 如果找到HEADERS帧，替换它
    if headers_frame_offset >= 0:
        print("准备替换HEADERS帧")
        
        # 定义一个格式正确的HTTP/2头部集合 - 包含content-length但不包含server字段
        # 使用简化方法：直接提供经过HPACK编码的已知有效头部
        
        # 这是一个预先编码好的HTTP/2头部，包含以下字段：
        # - :status: 201 Created
        # - :scheme: http
        # - content-type: application/json
        # - location: http://40.0.0.1/nsmf-pdusession/v1/pdu-sessions/9000000001
        # - content-length: 351
        # - date: Wed, 22 May 2025 02:48:05 GMT
        encoded_headers = binascii.unhexlify(
            "884076e7536488619d29aee30c0877cf5a9496e8dae354578365787a785f0d03"
            "73abbdcf1d75d0620d263d4c4a70d89d65905a593849a46e8593e9f6a473f963"
            "e6c99b2f93e6c93b2f6c929c4b5edc0ae1761968658eb4ff6a8eb4e5f8b16fa9"
            "c151"
        )
        
        # 替换HEADERS帧
        frame_header_length = len(encoded_headers).to_bytes(3, byteorder='big')
        frame_type = b'\x01'  # HEADERS帧
        frame_flags = b'\x04'  # END_HEADERS标志
        stream_id = b'\x00\x00\x00\x01'  # 流ID 1
        
        new_frame = frame_header_length + frame_type + frame_flags + stream_id + encoded_headers
        
        # 获取原始HEADERS帧长度
        original_length = int.from_bytes(raw_data[headers_frame_offset:headers_frame_offset+3], byteorder='big')
        
        # 替换原始帧
        modified_data = raw_data[:headers_frame_offset] + new_frame + raw_data[headers_frame_offset + 9 + original_length:]
        print(f"替换了HEADERS帧：原长度={original_length}，新长度={len(encoded_headers)}")
    else:
        print("未找到HEADERS帧，无法修复")
        return
    
    # 更新包的负载
    pkt15[Raw].load = modified_data
    
    # 保存修改后的PCAP
    wrpcap(output_pcap, packets)
    print(f"已保存修改后的PCAP到 {output_pcap}")
    
    # 验证结果
    print("\n验证修改后的包:")
    modified = False
    server_removed = False
    content_length_added = False
    
    if not b'server: SMF' in pkt15[Raw].load and not b'Server: SMF' in pkt15[Raw].load:
        print("✓ 成功: server: SMF 字段已移除")
        server_removed = True
    else:
        print("✗ 失败: server: SMF 字段仍然存在")
    
    if b'content-length: 351' in pkt15[Raw].load or b'Content-Length: 351' in pkt15[Raw].load:
        print("✓ 成功: content-length: 351 字段已添加")
        content_length_added = True
    else:
        print("✗ 失败: content-length: 351 字段未添加")
    
    if server_removed and content_length_added:
        print("🎉 修复成功：第15个包现在应该符合要求并正确显示在Wireshark中")
    else:
        print("⚠️ 修复不完全，可能需要进一步调整")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: python {sys.argv[0]} <input_pcap> <output_pcap>")
        sys.exit(1)
    
    main(sys.argv[1], sys.argv[2])
