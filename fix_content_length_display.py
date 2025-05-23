#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
针对第15个HTTP/2帧的content-length字段显示问题做特殊处理
使用明确的格式确保Wireshark能够正确识别
"""

import os
import sys
import logging
from scapy.all import *
from hpack import Encoder, Decoder
import re

# 设置日志
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s',
                   handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

def fix_pkt15_content_length(input_file, output_file):
    """专门处理第15个包中的content-length头部"""
    logger.info(f"读取PCAP文件: {input_file}")
    
    if not os.path.exists(input_file):
        logger.error(f"输入文件不存在: {input_file}")
        return False
    
    # 读取PCAP文件
    packets = rdpcap(input_file)
    logger.info(f"读取了 {len(packets)} 个包")
    
    if len(packets) < 15:
        logger.error(f"PCAP文件中只有 {len(packets)} 个包，少于15个")
        return False
    
    # 获取第15个包（索引14）
    pkt15 = packets[14]
    
    if not pkt15.haslayer(TCP) or not pkt15.haslayer(Raw):
        logger.error("第15个包没有TCP层或Raw层")
        return False
    
    # 获取原始数据
    raw_data = bytes(pkt15[Raw].load)
    logger.info(f"第15个包Raw数据长度: {len(raw_data)}")
    
    # 查找HTTP/2帧
    offset = 0
    frames = []
    modified = False
    
    while offset < len(raw_data) - 9:  # 确保至少有帧头
        try:
            # 解析帧头
            length = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            # 检查帧长度是否合理
            if 0 <= length < 16384 and offset + 9 + length <= len(raw_data):
                frame_data = raw_data[offset+9:offset+9+length]
                logger.debug(f"在偏移量 {offset} 找到帧: 类型={frame_type}, 长度={length}")
                
                # 如果是HEADERS帧(类型=1)，处理头部
                if frame_type == 1:
                    logger.info(f"处理HEADERS帧 at offset {offset}")
                    
                    # 解析HEADERS帧内容
                    try:
                        decoder = Decoder()
                        headers = decoder.decode(frame_data)
                        logger.info(f"成功解码头部，包含 {len(headers)} 个字段")
                        
                        # 检查是否存在content-length
                        has_content_length = False
                        content_length_value = "351"
                        
                        for name, value in headers:
                            name_str = name.decode() if isinstance(name, bytes) else str(name)
                            value_str = value.decode() if isinstance(value, bytes) else str(value)
                            
                            if name_str.lower() == "content-length":
                                has_content_length = True
                                logger.info(f"找到content-length: {value_str}")
                        
                        if not has_content_length:
                            logger.info("未找到content-length头部，准备添加")
                            
                            # 创建新的头部列表，确保content-length位于明显位置
                            new_headers = []
                            pseudo_headers = []  # 伪头部(以:开头的)必须在前
                            regular_headers = []  # 常规头部
                            
                            for name, value in headers:
                                name_str = name.decode() if isinstance(name, bytes) else str(name)
                                
                                if name_str.startswith(':'):
                                    pseudo_headers.append((name, value))
                                elif name_str.lower() == "server":
                                    # 跳过server字段，不添加到新头部中
                                    logger.info("跳过server字段")
                                else:
                                    regular_headers.append((name, value))
                            
                            # 重建头部，确保顺序正确
                            new_headers = pseudo_headers + regular_headers
                            
                            # 添加content-length字段，确保格式符合HTTP/2规范
                            if isinstance(new_headers[0][0], bytes):
                                content_length_name = b"content-length"
                                content_length_value = b"351"
                            else:
                                content_length_name = "content-length"
                                content_length_value = "351"
                                
                            new_headers.append((content_length_name, content_length_value))
                            logger.info(f"添加了content-length: {content_length_value}")
                            
                            # 使用encoder重新编码头部
                            encoder = Encoder()
                            new_frame_data = encoder.encode(new_headers)
                            
                            if len(new_frame_data) > 0:
                                # 构造新的帧
                                new_length = len(new_frame_data)
                                new_frame_header = raw_data[offset:offset+3].replace(
                                    int.to_bytes(length, 3, byteorder='big'),
                                    int.to_bytes(new_length, 3, byteorder='big')
                                ) + raw_data[offset+3:offset+9]
                                
                                # 替换原始帧
                                raw_data = raw_data[:offset] + new_frame_header + new_frame_data + raw_data[offset+9+length:]
                                logger.info(f"成功替换HEADERS帧，新长度: {new_length}")
                                modified = True
                                
                                # 由于数据长度变化，需要重新开始扫描
                                break
                        
                    except Exception as e:
                        logger.warning(f"解析HEADERS帧出错: {e}")
                        # 尝试直接二进制方式添加content-length
                        if b"content-length" not in frame_data.lower() and b"Content-Length" not in frame_data:
                            # 查找合适的插入点
                            insert_pos = -1
                            # 查找可能的HTTP/2头部字段结束位置
                            for pattern in [b'\r\n\r\n', b'\n\n', b'\r\n', b'\n']:
                                pos = frame_data.rfind(pattern)
                                if pos > 0:
                                    insert_pos = pos
                                    break
                            
                            if insert_pos > 0:
                                cl_header = b'\r\ncontent-length: 351'
                                new_frame_data = frame_data[:insert_pos] + cl_header + frame_data[insert_pos:]
                                
                                # 更新帧长度
                                new_length = len(new_frame_data)
                                new_frame_header = (int.to_bytes(new_length, 3, byteorder='big') + 
                                                  raw_data[offset+3:offset+9])
                                
                                # 替换原始帧
                                raw_data = raw_data[:offset] + new_frame_header + new_frame_data + raw_data[offset+9+length:]
                                logger.info(f"使用二进制方式添加content-length，新长度: {new_length}")
                                modified = True
                                
                                # 由于数据长度变化，需要重新开始扫描
                                break
                
                # 移动到下一个帧
                offset += 9 + length
            else:
                # 帧长度不合理，尝试查找下一个可能的帧
                offset += 1
        except Exception as e:
            logger.error(f"在偏移量 {offset} 处理帧时出错: {e}")
            offset += 1
    
    # 如果有修改，更新包并保存
    if modified:
        pkt15[Raw].load = raw_data
        wrpcap(output_file, packets)
        logger.info(f"修改后的PCAP已保存到 {output_file}")
        return True
    else:
        logger.warning("未对第15个包进行任何修改")
        return False

def main():
    """主函数"""
    if len(sys.argv) != 3:
        print(f"用法: python {sys.argv[0]} <input_pcap> <output_pcap>")
        print(f"例如: python {sys.argv[0]} pcap/N16_1513.pcap pcap/N16_fixed_cl.pcap")
        return
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    fix_pkt15_content_length(input_file, output_file)

if __name__ == "__main__":
    main()
