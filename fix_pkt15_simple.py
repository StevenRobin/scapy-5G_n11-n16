#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
简单脚本，为第15个报文同时添加server:SMF和content-length字段
特别针对截图中缺少content-length字段的问题
"""

from scapy.all import *
from scapy.layers.inet import TCP, IP
import sys

def fix_pkt15(input_file, output_file):
    """修复第15个报文的字段"""
    print(f"读取PCAP文件: {input_file}")
    
    # 读取PCAP文件
    packets = rdpcap(input_file)
    print(f"读取了 {len(packets)} 个报文")
    
    # 获取第15个报文(索引为14)
    if len(packets) < 15:
        print(f"错误: PCAP文件中只有 {len(packets)} 个报文，不足15个")
        return False
    
    pkt15 = packets[14]
    if not pkt15.haslayer(Raw):
        print("错误: 第15个报文没有原始数据负载")
        return False
    
    # 获取原始数据
    raw_data = bytes(pkt15[Raw].load)
    print(f"第15个报文原始数据长度: {len(raw_data)}")
    
    # 寻找HEADERS帧
    headers_found = False
    frame_start = 0
    
    # 查找HTTP/2 HEADERS帧
    for i in range(0, len(raw_data)-9, 1):
        # 检查帧类型是否为HEADERS(1)
        if raw_data[i+3] == 1:
            try:
                frame_len = int.from_bytes(raw_data[i:i+3], byteorder='big')
                # 验证帧长度合理
                if 10 < frame_len < 1000 and i + 9 + frame_len <= len(raw_data):
                    print(f"在偏移量 {i} 处找到可能的HEADERS帧，长度: {frame_len}")
                    # 验证是否确实是HTTP/2帧
                    frame_data = raw_data[i+9:i+9+frame_len]
                    if b':status' in frame_data or b':scheme' in frame_data or b':path' in frame_data:
                        print(f"确认为HTTP/2 HEADERS帧")
                        headers_found = True
                        frame_start = i
                        break
            except Exception as e:
                pass
    
    if not headers_found:
        print("错误: 未找到HTTP/2 HEADERS帧")
        return False
    
    # 提取帧头和帧数据
    frame_len = int.from_bytes(raw_data[frame_start:frame_start+3], byteorder='big')
    frame_type = raw_data[frame_start+3]
    frame_flags = raw_data[frame_start+4]
    stream_id = int.from_bytes(raw_data[frame_start+5:frame_start+9], byteorder='big') & 0x7FFFFFFF
    
    frame_header = raw_data[frame_start:frame_start+9]
    frame_data = raw_data[frame_start+9:frame_start+9+frame_len]
    
    print(f"HEADERS帧: 类型={frame_type}, 长度={frame_len}, 标志={frame_flags}, 流ID={stream_id}")
    print(f"帧数据前32字节: {frame_data[:32].hex()}")
    
    # 检查是否已有所需字段
    server_exists = b'server: SMF' in frame_data.lower() or b'Server: SMF' in frame_data
    content_length_exists = b'content-length:' in frame_data.lower() or b'Content-Length:' in frame_data
    
    print(f"字段检查 - Server: {'存在' if server_exists else '不存在'}, Content-Length: {'存在' if content_length_exists else '不存在'}")
    
    modified = False
    
    # 添加缺失的字段
    if not server_exists:
        print("添加 server: SMF 字段")
        frame_data = frame_data + b'\r\nserver: SMF'
        modified = True
    
    if not content_length_exists:
        print("添加 content-length: 351 字段")
        frame_data = frame_data + b'\r\ncontent-length: 351'
        modified = True
    
    if not modified:
        print("无需修改，所有字段已存在")
        return True
    
    # 更新帧长度和帧头
    new_frame_len = len(frame_data)
    new_frame_header = new_frame_len.to_bytes(3, byteorder='big') + frame_header[3:]
    
    print(f"更新帧长度: {frame_len} -> {new_frame_len}")
    
    # 构造新的报文负载
    new_payload = bytearray(raw_data)
    new_payload[frame_start:frame_start+9] = new_frame_header
    new_payload[frame_start+9:frame_start+9+frame_len] = frame_data[:frame_len]
    
    # 如果新数据长于原数据，需要在适当位置插入
    if new_frame_len > frame_len:
        extra_data = frame_data[frame_len:]
        new_payload = new_payload[:frame_start+9+frame_len] + extra_data + new_payload[frame_start+9+frame_len:]
    
    # 更新报文
    pkt15[Raw].load = bytes(new_payload)
    
    # 删除校验和以便自动重新计算
    del pkt15[IP].chksum
    if pkt15.haslayer(TCP):
        del pkt15[TCP].chksum
    
    # 保存修改后的报文
    print(f"保存修改后的PCAP文件到: {output_file}")
    wrpcap(output_file, packets)
    
    # 验证修改
    verify_packets = rdpcap(output_file)
    verify_pkt15 = verify_packets[14]
    verify_data = bytes(verify_pkt15[Raw].load)
    
    server_exists = b'server: SMF' in verify_data.lower() or b'Server: SMF' in verify_data
    content_length_exists = b'content-length:' in verify_data.lower() or b'Content-Length:' in verify_data
    
    print(f"验证结果 - Server: {'存在' if server_exists else '不存在'}, Content-Length: {'存在' if content_length_exists else '不存在'}")
    
    if server_exists and content_length_exists:
        print("修复成功!")
        return True
    else:
        print("修复失败!")
        return False

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <input_pcap> [output_pcap]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.replace('.pcap', '_fixed.pcap')
    
    if fix_pkt15(input_file, output_file):
        print("处理成功完成")
    else:
        print("处理失败")

if __name__ == "__main__":
    main()
