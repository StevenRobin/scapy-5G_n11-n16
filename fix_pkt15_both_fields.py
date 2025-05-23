#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
简单脚本，专门用于同时添加 server:SMF 和 content-length 字段到第15号报文
"""
from scapy.all import rdpcap, wrpcap, Raw
from scapy.layers.inet import IP, TCP
import os
import sys

def main():
    """主函数"""
    # 解析命令行参数
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <input_pcap> [output_pcap]")
        return False
    
    # 设置输入和输出文件
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "pcap/N16_fixed_pkt15.pcap"
    
    print(f"开始处理文件: {input_file}")
    
    try:
        # 读取PCAP文件
        packets = rdpcap(input_file)
        print(f"读取了 {len(packets)} 个报文")
        
        if len(packets) < 15:
            print("错误: PCAP文件中的报文数量不足")
            return False
        
        # 获取第15号报文(索引为14)
        pkt15 = packets[14]
        if not pkt15.haslayer(Raw):
            print("错误: 第15号报文没有负载数据")
            return False
        
        # 提取负载数据
        raw_data = bytes(pkt15[Raw].load)        print(f"第15号报文原始负载长度: {len(raw_data)}")
        print(f"原始数据前32字节: {raw_data[:32].hex()}")
        
        # 解析HTTP/2帧
        offset = 0
        modified = False
        
        # 修改后的帧数据
        new_frames = []
        
        # 尝试查找HTTP/2帧标记
        http2_frame_found = False
        for i in range(len(raw_data) - 9):
            if raw_data[i+3] in [0, 1, 8, 9]:  # 常见的HTTP/2帧类型
                possible_len = int.from_bytes(raw_data[i:i+3], byteorder='big')
                if 0 < possible_len < 16384 and i + 9 + possible_len <= len(raw_data):
                    print(f"可能的HTTP/2帧发现于偏移量 {i}, 类型: {raw_data[i+3]}, 长度: {possible_len}")
                    http2_frame_found = True
                    break
        
        print(f"HTTP/2帧检测: {'找到' if http2_frame_found else '未找到'}")
        
        while offset + 9 <= len(raw_data):
            # 解析帧头
            try:
                frame_len = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
                frame_type = raw_data[offset+3]
                frame_flags = raw_data[offset+4]
                stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
                
                frame_headers = raw_data[offset:offset+9]
                frame_data = raw_data[offset+9:offset+9+frame_len]
                
                print(f"帧类型: {frame_type}, 长度: {frame_len}, 标志: {frame_flags}, 流ID: {stream_id}")
                
                # 如果是HEADERS帧，添加所需字段
                if frame_type == 1:  # HEADERS帧类型为1
                    print("发现HEADERS帧，添加所需字段")
                    
                    # 检查是否存在server字段
                    server_exists = (b'server: SMF' in frame_data.lower() or 
                                     b'Server: SMF' in frame_data or
                                     b'server:SMF' in frame_data.lower())
                    
                    # 检查是否存在content-length字段
                    content_length_exists = (b'content-length:' in frame_data.lower() or
                                             b'Content-Length:' in frame_data)
                    
                    print(f"字段检查 - Server: {server_exists}, Content-Length: {content_length_exists}")
                    
                    # 如果缺失server字段，添加它
                    if not server_exists:
                        print("添加 server:SMF 字段")
                        frame_data = frame_data + b'\r\nserver: SMF'
                        modified = True
                    
                    # 如果缺失content-length字段，添加它
                    if not content_length_exists:
                        print("添加 content-length: 351 字段")
                        frame_data = frame_data + b'\r\ncontent-length: 351'  # 将值改为351以匹配截图
                        modified = True
                    
                    # 更新帧长度
                    if modified:
                        frame_len = len(frame_data)
                        frame_headers = frame_len.to_bytes(3, byteorder='big') + frame_headers[3:]
                        print(f"更新帧长度为: {frame_len}")
                
                # 保存帧
                new_frames.append((frame_headers, frame_data))
                
                # 移动到下一帧
                offset += 9 + frame_len
                
            except Exception as e:
                print(f"解析帧时出错: {e}")
                break
        
        # 如果进行了修改，重建负载
        if modified:
            print("重建报文负载...")
            new_payload = b''
            for frame_headers, frame_data in new_frames:
                new_payload += frame_headers + frame_data
            
            # 更新报文
            pkt15[Raw].load = new_payload
            print(f"更新后的负载长度: {len(new_payload)}")
            
            # 重新计算校验和
            del pkt15[IP].len
            del pkt15[IP].chksum
            if pkt15.haslayer(TCP):
                del pkt15[TCP].chksum
        
        # 保存PCAP文件
        print(f"保存修改后的PCAP文件: {output_file}")
        wrpcap(output_file, packets)
        print("保存成功！")
        
        # 验证修改结果
        print("验证修改结果...")
        verification = rdpcap(output_file)
        pkt15_fixed = verification[14]
        raw_data_fixed = bytes(pkt15_fixed[Raw].load)
        
        server_found = (b'server: SMF' in raw_data_fixed.lower() or
                        b'Server: SMF' in raw_data_fixed or
                        b'server:SMF' in raw_data_fixed.lower())
        
        content_length_found = (b'content-length:' in raw_data_fixed.lower() or
                               b'Content-Length:' in raw_data_fixed)
        
        if server_found:
            print("✓ server:SMF 字段已添加")
        else:
            print("✗ 未找到 server:SMF 字段")
        
        if content_length_found:
            print("✓ content-length 字段已添加")
        else:
            print("✗ 未找到 content-length 字段")
        
        if server_found and content_length_found:
            print("修复成功！")
            return True
        else:
            print("部分修复失败，请检查日志")
            return False
    
    except Exception as e:
        print(f"处理过程中出错: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    main()
