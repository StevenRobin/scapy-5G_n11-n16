#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
分析第15个报文的HTTP/2头部，特别关注status字段和content-length字段
"""

import os
import sys
import logging
import binascii
from scapy.all import rdpcap, Raw

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def print_hex_dump(data, prefix=''):
    """打印十六进制格式的数据"""
    hex_dump = binascii.hexlify(data).decode()
    logger.info(f"{prefix}十六进制数据: {hex_dump}")

def find_status_field(raw_data):
    """查找status字段"""
    status_patterns = [
        b':status:', b':status: ',
        b'88', b'89'  # HPACK编码中常见的:status:字段编码
    ]
    
    for pattern in status_patterns:
        pos = raw_data.find(pattern)
        if pos >= 0:
            logger.info(f"找到status字段模式 {pattern} 在位置 {pos}")
            # 打印周围的数据
            context_start = max(0, pos - 10)
            context_end = min(len(raw_data), pos + 30)
            context = raw_data[context_start:context_end]
            print_hex_dump(context, f"status字段上下文 (位置 {pos}): ")
            
            # 尝试识别status值
            if pattern in [b':status:', b':status: ']:
                value_start = pos + len(pattern)
                # 尝试找到值的结束位置
                for end_char in [b'\r', b'\n', b' ', b';']:
                    value_end = raw_data.find(end_char, value_start)
                    if value_end > 0:
                        status_value = raw_data[value_start:value_end]
                        logger.info(f"status值: {status_value}")
                        break

def find_content_length_field(raw_data):
    """查找content-length字段"""
    cl_patterns = [
        b'content-length:', b'content-length: ',
        b'Content-Length:', b'Content-Length: '
    ]
    
    for pattern in cl_patterns:
        pos = raw_data.find(pattern)
        if pos >= 0:
            logger.info(f"找到content-length字段模式 {pattern} 在位置 {pos}")
            # 打印周围的数据
            context_start = max(0, pos - 10)
            context_end = min(len(raw_data), pos + 40)
            context = raw_data[context_start:context_end]
            print_hex_dump(context, f"content-length字段上下文 (位置 {pos}): ")
            
            # 尝试识别content-length值
            value_start = pos + len(pattern)
            # 尝试找到值的结束位置
            for end_char in [b'\r', b'\n', b' ', b';']:
                value_end = raw_data.find(end_char, value_start)
                if value_end > 0:
                    cl_value = raw_data[value_start:value_end]
                    logger.info(f"content-length值: {cl_value}")
                    break
    
    # 特别检查hardcoded的content-length部分
    hardcoded_cl = b'content-length: 351'
    pos = raw_data.find(hardcoded_cl)
    if pos >= 0:
        logger.info(f"找到硬编码的content-length: 351在位置 {pos}")
        context_start = max(0, pos - 10)
        context_end = min(len(raw_data), pos + 40)
        context = raw_data[context_start:context_end]
        print_hex_dump(context, "硬编码的content-length上下文: ")

def analyze_header_frame(raw_data):
    """分析HTTP/2头部帧"""
    logger.info("开始分析HTTP/2头部帧")
    
    # 尝试找到头部帧（类型0x1）
    offset = 0
    while offset < len(raw_data) - 9:  # 9字节是帧头的长度
        try:
            frame_length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            
            # 检查是否是有效的HTTP/2帧
            if frame_length >= 0 and frame_length < 16384 and offset + 9 + frame_length <= len(raw_data):
                logger.info(f"在位置 {offset} 找到帧，类型: {frame_type}，长度: {frame_length}")
                
                # 如果是HEADERS帧
                if frame_type == 1:  # HEADERS帧
                    logger.info(f"在位置 {offset} 找到HEADERS帧")
                    # 获取帧头部和载荷
                    frame_header = raw_data[offset:offset+9]
                    frame_payload = raw_data[offset+9:offset+9+frame_length]
                    
                    logger.info(f"HEADERS帧头: {binascii.hexlify(frame_header).decode()}")
                    logger.info(f"HEADERS帧长度: {frame_length} 字节")
                    print_hex_dump(frame_payload, "HEADERS帧载荷: ")
                    
                    # 分析头部字段
                    find_status_field(frame_payload)
                    find_content_length_field(frame_payload)
                    
                    # 在HEADERS帧中特别查找"content-length: 351"的HPACK表示
                    cl_hex = b'content-length: 351'
                    logger.info(f"在HEADERS帧中查找'{cl_hex}'的表示")
                    
                    # 检查known的HPACK编码表示
                    known_cl_encodings = [
                        # content-length: 351的一些可能的HPACK编码
                        bytes.fromhex("3f6423636f6e74656e742d6c656e6774683a20333531"),
                        bytes.fromhex("6423636f6e74656e742d6c656e6774683a20333531"),
                        bytes.fromhex("636f6e74656e742d6c656e6774683a20333531")
                    ]
                    
                    for encoding in known_cl_encodings:
                        if encoding in frame_payload:
                            logger.info(f"找到可能的content-length: 351 HPACK编码: {binascii.hexlify(encoding).decode()}")
                
                offset += 9 + frame_length
            else:
                offset += 1
        except Exception as e:
            logger.error(f"解析帧时出错: {e}")
            offset += 1

def main():
    """主函数"""
    pcap_file = "pcap/N16_fixed_final.pcap"
    
    if not os.path.exists(pcap_file):
        logger.error(f"文件不存在: {pcap_file}")
        return
    
    logger.info(f"读取PCAP文件: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    if len(packets) < 15:
        logger.error(f"PCAP只包含 {len(packets)} 个报文，少于15个")
        return
    
    # 获取第15个报文（索引14）
    pkt15 = packets[14]
    
    if not pkt15.haslayer(Raw):
        logger.error("第15个报文没有Raw层")
        return
    
    raw_data = bytes(pkt15[Raw].load)
    logger.info(f"第15个报文负载长度: {len(raw_data)} 字节")
    print_hex_dump(raw_data[:50], "负载前50字节: ")
    
    # 分析头部帧
    analyze_header_frame(raw_data)
    
    # 直接在整个负载中查找相关字段
    find_status_field(raw_data)
    find_content_length_field(raw_data)

if __name__ == "__main__":
    main()
