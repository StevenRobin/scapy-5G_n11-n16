#!/usr/bin/env python
# coding: utf-8

import logging
import sys
from scapy.all import *
from scapy.layers.inet import TCP
from hpack import Decoder

# 配置日志输出到控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

def parse_http2_headers(packet_data):
    """尝试解析HTTP/2头部字段"""
    try:
        # 检查是否是HTTP/2头部帧
        frame_length = int.from_bytes(packet_data[0:3], byteorder='big')
        frame_type = packet_data[3]
        
        if frame_type != 1:  # 1表示HEADERS帧
            logger.warning(f"不是HEADERS帧，而是类型 {frame_type}")
            return None
        
        logger.info(f"找到HTTP/2 HEADERS帧，长度: {frame_length}")
        
        # 跳过9字节的帧头
        headers_block_fragment = packet_data[9:9+frame_length]
        
        # 尝试使用HPACK解码
        try:
            decoder = Decoder()
            headers = decoder.decode(headers_block_fragment)
            
            # 将迭代器转换为列表以便可以多次使用
            header_list = list(headers)
            header_count = len(header_list)
            
            logger.info(f"成功解析HTTP/2头部字段，找到 {header_count} 个字段")
            
            for i, (name, value) in enumerate(header_list):
                name_str = name.decode('utf-8', errors='ignore') if isinstance(name, bytes) else name
                value_str = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else value
                logger.info(f"  头部字段 #{i+1}: {name_str} = {value_str}")
            
            return header_list
        except Exception as e:
            logger.error(f"HPACK解码失败: {e}")
            
            # 尝试二进制搜索关键字段
            logger.info("尝试通过二进制搜索查找关键字段")
            
            # 尝试查找:status字段
            status_pattern = b':status'
            pos = headers_block_fragment.find(status_pattern)
            if pos >= 0:
                logger.info(f"在位置 {pos} 找到:status字段")
                # 尝试提取值
                val_start = pos + len(status_pattern)
                val_end = -1
                for end_mark in [b'\r\n', b'\n', b';']:
                    end_pos = headers_block_fragment.find(end_mark, val_start)
                    if end_pos > 0:
                        val_end = end_pos
                        break
                
                if val_end > val_start:
                    status_value = headers_block_fragment[val_start:val_end].strip()
                    logger.info(f"Status值: {status_value}")
            
            # 尝试查找location字段
            location_pattern = b'location'
            pos = headers_block_fragment.find(location_pattern)
            if pos >= 0:
                logger.info(f"在位置 {pos} 找到location字段")
                # 尝试提取值
                val_start = pos + len(location_pattern)
                val_end = -1
                for end_mark in [b'\r\n', b'\n', b';']:
                    end_pos = headers_block_fragment.find(end_mark, val_start)
                    if end_pos > 0:
                        val_end = end_pos
                        break
                
                if val_end > val_start:
                    location_value = headers_block_fragment[val_start:val_end].strip()
                    logger.info(f"Location值: {location_value}")
            
            # 尝试查找content-type字段
            content_type_pattern = b'content-type'
            pos = headers_block_fragment.find(content_type_pattern)
            if pos >= 0:
                logger.info(f"在位置 {pos} 找到content-type字段")
                # 尝试提取值
                val_start = pos + len(content_type_pattern)
                val_end = -1
                for end_mark in [b'\r\n', b'\n', b';']:
                    end_pos = headers_block_fragment.find(end_mark, val_start)
                    if end_pos > 0:
                        val_end = end_pos
                        break
                
                if val_end > val_start:
                    content_type_value = headers_block_fragment[val_start:val_end].strip()
                    logger.info(f"Content-Type值: {content_type_value}")
            
            return None
    except Exception as e:
        logger.error(f"解析HTTP/2头部时发生错误: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def main():
    # 加载PCAP文件
    pcap_path = 'pcap/N16_1507.pcap'
    logger.info(f"加载PCAP文件: {pcap_path}")
    
    try:
        packets = rdpcap(pcap_path)
        logger.info(f"成功加载PCAP文件，共 {len(packets)} 个报文")
        
        # 获取第15个报文 (索引14)
        if len(packets) >= 15:
            pkt15 = packets[14]
            logger.info(f"处理第15号报文")
            
            # 检查是否包含TCP负载
            if TCP in pkt15 and Raw in pkt15[TCP]:
                raw_data = pkt15[TCP].payload.load
                logger.info(f"报文15包含 {len(raw_data)} 字节的TCP负载")
                
                # 解析HTTP/2头部
                headers = parse_http2_headers(raw_data)
                
                if headers:
                    logger.info("成功解析第15号报文的HTTP/2头部")
                    
                    # 检查是否包含我们期望的关键字段
                    has_status = False
                    has_location = False
                    has_content_type = False
                    
                    for name, value in headers:
                        name_str = name.decode('utf-8', errors='ignore').lower() if isinstance(name, bytes) else name.lower()
                        
                        if name_str == ':status':
                            has_status = True
                            logger.info(f"找到Status字段: {value}")
                        elif name_str == 'location':
                            has_location = True
                            logger.info(f"找到Location字段: {value}")
                        elif name_str == 'content-type':
                            has_content_type = True
                            logger.info(f"找到Content-Type字段: {value}")
                    
                    # 总结
                    if has_status and has_location and has_content_type:
                        logger.info("第15号报文包含所有必要的头部字段! 修复成功!")
                    else:
                        missing = []
                        if not has_status:
                            missing.append('Status')
                        if not has_location:
                            missing.append('Location')
                        if not has_content_type:
                            missing.append('Content-Type')
                        
                        logger.warning(f"第15号报文仍然缺少以下头部字段: {', '.join(missing)}")
                else:
                    logger.warning("无法完全解析第15号报文的HTTP/2头部")
            else:
                logger.warning("第15号报文不包含TCP负载")
        else:
            logger.warning(f"PCAP文件中没有足够的报文，只有 {len(packets)} 个")
    except Exception as e:
        logger.error(f"处理PCAP文件时发生错误: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()
