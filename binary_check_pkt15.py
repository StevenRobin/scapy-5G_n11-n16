#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
直接通过二进制检查PCAP验证第15个报文中的三个问题是否已修复:
1. 检查`:status: 201` (HPACK编码 0x8840)
2. 确认没有`:scheme: http` (HPACK编码 0x86)
3. 检查`content-length: 351` 
"""

from scapy.all import *
import sys
import binascii

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
    
    # 查找第一个HEADERS帧
    offset = 0
    headers_block = None
    
    while offset < len(raw_data):
        if offset + 9 > len(raw_data):
            break
            
        try:
            frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            
            # 找到HEADERS帧
            if frame_type == 1:  # HEADERS帧
                headers_block = raw_data[offset+9:offset+9+frame_length]
                print(f"找到HEADERS帧, 长度: {frame_length}")
                break
                
            offset += 9 + frame_length
        except Exception as e:
            print(f"解析帧出错: {e}")
            offset += 1
    
    if not headers_block:
        print("未找到HEADERS帧!")
        return
        
    # 输出完整的HEADERS帧十六进制表示，便于分析
    hex_headers = binascii.hexlify(headers_block).decode('ascii')
    print(f"\nHEADERS帧十六进制:\n{hex_headers}")
    
    # 1. 检查`:status: 201` (HPACK编码 0x8840)
    has_status_201 = b'\x88\x40' in headers_block
    print(f"\n1. ':status: 201' (HPACK编码 8840): {'√ 存在' if has_status_201 else '× 不存在'}")
    
    # 2. 确认没有`:scheme: http` (HPACK编码 0x86)
    has_scheme = b'\x86' in headers_block
    # 这是一个简单检查，在实际中需要更详细分析，因为0x86可能是其他字段的一部分
    print(f"2. ':scheme: http' (HPACK编码 86): {'× 存在 (可能误报，需进一步分析)' if has_scheme else '√ 不存在'}")
    
    # 3. 检查`content-length: 351` 
    # HPACK编码较长，我们直接搜索十六进制中的 'content-length' 和 '351'
    has_cl_text = b'content-length' in headers_block.lower() or b'Content-Length' in headers_block
    has_cl_351_text = (b'content-length: 351' in headers_block.lower() or 
                       b'Content-Length: 351' in headers_block)
    
    # 检查十六进制表示中是否包含"content-length: 351"的ASCII码
    cl_hex = '636f6e74656e742d6c656e6774683a20333531'  # "content-length: 351"的十六进制
    has_cl_hex = cl_hex in hex_headers.lower()
    
    print(f"3. 'content-length: 351': {'√ 存在' if has_cl_text and (has_cl_351_text or has_cl_hex) else '× 不存在'}")
    
    # 总结检查结果  
    all_ok = has_status_201 and (not has_scheme) and (has_cl_text and (has_cl_351_text or has_cl_hex))
    
    if all_ok:
        print("\n✅ 所有检查通过! 修复成功!")
    else:
        print("\n❌ 至少一项检查未通过，修复不完全!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"使用方法: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    main(sys.argv[1])
