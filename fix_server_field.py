#!/usr/bin/env python3
"""
只添加 server: SMF 字段到第15号报文的超简化脚本
"""
from scapy.all import rdpcap, wrpcap, Raw
from scapy.layers.inet import IP, TCP
import sys
import os
import traceback

def fix_server_field():
    """添加server: SMF字段"""
    input_file = "pcap/N16_fixed_pkt15.pcap"
    output_file = "pcap/N16_fixed_both.pcap"
    
    print(f"开始处理文件: {input_file}")
    sys.stdout.flush()  # 强制输出缓冲区
    
    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        print(f"错误: 输入文件 {input_file} 不存在")
        return False
    
    try:
        # 读取PCAP文件
        print("读取PCAP文件...")
        sys.stdout.flush()
        packets = rdpcap(input_file)
        print(f"读取了 {len(packets)} 个报文")
        sys.stdout.flush()
        
        # 获取第15号报文
        pkt15 = packets[14]
        if not pkt15.haslayer(Raw):
            print("错误: 第15号报文没有负载数据")
            return False
        
        # 提取负载
        raw_data = bytes(pkt15[Raw].load)
        print(f"第15号报文原始负载长度: {len(raw_data)}")
        
        # 查找第一个HEADERS帧
        offset = 0
        modified = False
        
        while offset + 9 <= len(raw_data):
            # 解析帧头
            frame_len = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            frame_flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            print(f"帧类型: {frame_type}, 长度: {frame_len}")
            
            # 如果是HEADERS帧，添加server: SMF字段
            if frame_type == 1:  # HEADERS帧类型为1
                print("发现HEADERS帧")
                
                # 提取帧数据
                frame_data = raw_data[offset+9:offset+9+frame_len]
                
                # 检查是否已有server字段
                if (b'server: SMF' not in frame_data.lower() and
                    b'Server: SMF' not in frame_data and
                    b'server:SMF' not in frame_data.lower()):
                    print("添加server: SMF字段")
                    
                    # 在最简单的情况下，直接修改帧数据
                    frame_data = frame_data + b'\r\nserver: SMF'
                    
                    # 计算新的帧长度
                    new_frame_len = len(frame_data)
                    print(f"新的帧长度: {new_frame_len}")
                    
                    # 构建新的帧头
                    new_frame_header = new_frame_len.to_bytes(3, byteorder='big')
                    new_frame_header += bytes([frame_type])
                    new_frame_header += bytes([frame_flags])
                    new_frame_header += (stream_id & 0x7FFFFFFF).to_bytes(4, byteorder='big')
                    
                    # 构建新的负载
                    new_payload = raw_data[:offset]
                    new_payload += new_frame_header
                    new_payload += frame_data
                    new_payload += raw_data[offset+9+frame_len:]
                    
                    # 更新报文负载
                    pkt15[Raw].load = new_payload
                    print(f"更新后的负载长度: {len(new_payload)}")
                    
                    # 重新计算校验和
                    del pkt15[IP].len
                    del pkt15[IP].chksum
                    if pkt15.haslayer(TCP):
                        del pkt15[TCP].chksum
                    
                    modified = True
                    break  # 只修改第一个HEADERS帧
                else:
                    print("server: SMF字段已存在")
            
            # 移动到下一帧
            offset += 9 + frame_len
        
        # 保存修改后的PCAP文件
        if modified:
            print(f"保存修改后的PCAP文件: {output_file}")
            wrpcap(output_file, packets)
            print("保存成功！")
            
            # 验证修改结果
            verification = rdpcap(output_file)
            pkt15_fixed = verification[14]
            raw_data_fixed = bytes(pkt15_fixed[Raw].load)
            
            if (b'server: SMF' in raw_data_fixed or
                b'Server: SMF' in raw_data_fixed or
                b'server:SMF' in raw_data_fixed):
                print("验证成功: server: SMF字段已添加")
                return True
            else:
                print("验证失败: 未找到server: SMF字段")
                return False
        else:
            print("未进行任何修改")
            return False
    
    except Exception as e:
        print(f"处理过程中出错: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    fix_server_field()
