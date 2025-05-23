#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
检查第15号报文的DATA帧中的JSON格式是否正确
"""

from scapy.all import *
import sys
import json
import binascii

def main(pcap_file):
    """主函数"""
    print(f"读取PCAP文件: {pcap_file}")
    
    # 读取PCAP文件
    try:
        packets = rdpcap(pcap_file)
        print(f"读取了 {len(packets)} 个报文")
        sys.stdout.flush()  # 强制输出
    except Exception as e:
        print(f"读取PCAP文件时出错: {e}")
        sys.stdout.flush()  # 强制输出
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
    
    # 查找DATA帧
    offset = 0
    data_content = None
    
    while offset < len(raw_data):
        if offset + 9 > len(raw_data):
            break
            
        try:
            frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            
            # 找到DATA帧
            if frame_type == 0:  # DATA帧
                print(f"找到DATA帧, 位置: {offset}, 长度: {frame_length}")
                data_content = raw_data[offset+9:offset+9+frame_length]
                break
            
            # 移动到下一个帧
            offset += 9 + frame_length
        except Exception as e:
            print(f"解析帧出错: {e}")
            offset += 1
    
    if data_content is None:
        print("未找到DATA帧!")
        return
    
    # 将DATA帧内容转换为文本
    try:
        json_text = data_content.decode('utf-8', errors='replace')
        print("JSON文本内容:")
        print(json_text)
        
        # 尝试解析JSON
        try:
            json_data = json.loads(json_text)
            print("\nJSON解析成功! 格式正确。")
            print("解析后的JSON数据:")
            print(json.dumps(json_data, indent=2, ensure_ascii=False))
        except json.JSONDecodeError as e:
            print(f"\nJSON解析失败: {e}")
            
            # 错误定位
            print(f"错误位置: 第{e.lineno}行, 第{e.colno}列")
            print(f"错误内容: {e.msg}")
            
            # 显示问题位置的上下文
            lines = json_text.split('\n')
            if e.lineno <= len(lines):
                error_line = lines[e.lineno-1]
                print(f"问题行: {error_line}")
                if e.colno > 0:
                    print(" " * (e.colno-1) + "^-- 错误位置")
    except UnicodeDecodeError:
        print("无法将DATA帧内容解码为UTF-8文本")
        print("十六进制内容:")
        print(binascii.hexlify(data_content).decode())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    main(sys.argv[1])
