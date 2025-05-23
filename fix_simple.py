#!/usr/bin/env python3
"""
直接修复第15号报文中的content-length和server:SMF字段
简化版本，避免任何复杂代码和缩进问题
"""
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP
import os
import sys

def print_log(msg):
    """打印日志"""
    print(f"LOG: {msg}")

def main():
    """主函数"""
    # 检查命令行参数
    if len(sys.argv) != 3:
        print("用法: python fix_simple.py <输入PCAP> <输出PCAP>")
        return
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # 确保输入文件存在
    if not os.path.exists(input_file):
        print(f"错误: 输入文件 {input_file} 不存在")
        return
    
    # 确保输出目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print_log(f"读取PCAP文件: {input_file}")
    try:
        # 读取PCAP文件
        packets = rdpcap(input_file)
        print_log(f"读取了 {len(packets)} 个报文")
        
        if len(packets) < 15:
            print("错误: PCAP文件中报文数量不足")
            return
        
        # 获取第15个报文 (索引为14)
        pkt15 = packets[14]
        if not pkt15.haslayer(Raw):
            print("错误: 第15个报文没有负载")
            return
        
        # 获取原始负载
        raw_data = bytes(pkt15[Raw].load)
        print_log(f"第15号报文原始负载长度: {len(raw_data)}")
        
        # 简单粗暴地修改负载以确保包含所需字段
        modified_data = raw_data
        
        # 添加 server:SMF 字段
        if b'server: SMF' not in modified_data and b'Server: SMF' not in modified_data:
            print_log("添加 server:SMF 字段")
            # 尝试找到合适的插入位置
            pos = -1
            for marker in [b'\r\n\r\n', b'\n\n', b'\r\n', b'\n']:
                pos = modified_data.find(marker)
                if pos > 0:
                    break
            
            if pos > 0:
                modified_data = modified_data[:pos] + b'\r\nserver: SMF' + modified_data[pos:]
                print_log("成功添加 server:SMF 字段")
        
        # 添加 content-length 字段
        if b'content-length:' not in modified_data.lower() and b'Content-Length:' not in modified_data:
            print_log("添加 content-length 字段")
            # 尝试找到合适的插入位置
            pos = -1
            for marker in [b'\r\n\r\n', b'\n\n', b'\r\n', b'\n']:
                pos = modified_data.find(marker)
                if pos > 0:
                    break
            
            if pos > 0:
                modified_data = modified_data[:pos] + b'\r\ncontent-length: 351' + modified_data[pos:]
                print_log("成功添加 content-length 字段")
        
        # 更新报文负载
        if modified_data != raw_data:
            pkt15[Raw].load = modified_data
            print_log("更新了报文负载")
            
            # 重新计算校验和
            del pkt15[IP].len
            del pkt15[IP].chksum
            if pkt15.haslayer(TCP):
                del pkt15[TCP].chksum
        
        # 保存修改后的PCAP
        print_log(f"保存修改后的PCAP到: {output_file}")
        wrpcap(output_file, packets)
        print_log("保存成功")
        print("修复完成！")
    
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
