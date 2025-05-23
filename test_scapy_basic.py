#!/usr/bin/env python3
"""
超级简化版 - 只读取PCAP文件并保存，不做任何修改
用于测试基本的 scapy 功能
"""
import sys
import os
from scapy.all import rdpcap, wrpcap
import traceback

def main():
    # 设置输入和输出文件名
    input_file = "pcap/N16_create_16p.pcap"
    output_file = "pcap/test_output.pcap"
    
    print(f"当前工作目录: {os.getcwd()}")
    print(f"输入文件: {os.path.abspath(input_file)}")
    print(f"输出文件: {os.path.abspath(output_file)}")
    
    # 检查输入文件是否存在
    if os.path.exists(input_file):
        print(f"输入文件存在，大小: {os.path.getsize(input_file)} 字节")
    else:
        print(f"错误: 输入文件不存在")
        # 检查pcap目录
        if os.path.exists("pcap"):
            print("pcap目录存在")
            # 列出pcap目录中的文件
            print("pcap目录内容:")
            for fname in os.listdir("pcap"):
                print(f"  - {fname}")
        else:
            print("pcap目录不存在")
        return
    
    # 创建输出目录（如果不存在）
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"创建了输出目录: {output_dir}")
    
    try:
        # 读取PCAP文件
        print("开始读取PCAP文件...")
        packets = rdpcap(input_file)
        print(f"成功读取PCAP文件，包含 {len(packets)} 个报文")
        
        # 直接保存PCAP文件，不做任何修改
        print(f"开始保存PCAP文件到: {output_file}")
        wrpcap(output_file, packets)
        print(f"PCAP文件保存成功")
        
        # 验证输出文件
        if os.path.exists(output_file):
            print(f"输出文件已创建，大小: {os.path.getsize(output_file)} 字节")
        else:
            print("错误: 输出文件未创建")
    
    except Exception as e:
        print(f"发生错误: {e}")
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
