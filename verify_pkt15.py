#!/usr/bin/env python3
# 验证第15号报文的content-length和server:SMF字段是否都正确保留
from scapy.all import rdpcap, wrpcap, Raw
from scapy.layers.inet import IP, TCP
import re
import logging
import os
import sys
import traceback
import binascii

# 配置日志记录器
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("verify_pkt15.log", mode="w"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def hexdump(data, length=16):
    """将二进制数据转换为十六进制形式，方便查看"""
    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hexa = ' '.join(['%02x' % x for x in chunk])
        text = ''.join([chr(x) if 32 <= x <= 126 else '.' for x in chunk])
        result.append('%04x:  %-*s  %s' % (i, length*3, hexa, text))
    return '\n'.join(result)

def process_pcap_file(pcap_file):
    """处理PCAP文件，检查第15号报文"""
    logger.info(f"处理PCAP文件: {pcap_file}")
    
    try:
        # 读取PCAP文件
        packets = rdpcap(pcap_file)
        if len(packets) < 15:
            logger.error(f"PCAP文件中的报文数量不足，只有 {len(packets)} 个报文")
            return False
        
        # 获取第15号报文（索引为14，因为索引从0开始）
        pkt15 = packets[14]
        
        if not pkt15.haslayer(TCP) or not pkt15.haslayer(Raw):
            logger.error("第15号报文不是TCP报文或没有负载")
            return False
        
        # 提取原始负载
        raw_data = bytes(pkt15[Raw].load)
        logger.info(f"第15号报文原始负载长度: {len(raw_data)}")
        
        # 查找HEADERS帧
        offset = 0
        found_headers_frame = False
        
        while offset + 9 < len(raw_data):
            # 解析帧头
            frame_len = int.from_bytes(raw_data[offset:offset+3], byteorder='big')
            frame_type = raw_data[offset+3]
            frame_flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
            
            logger.info(f"帧类型: {frame_type}, 长度: {frame_len}, 标志: {frame_flags}, 流ID: {stream_id}")
            
            # 检查是否为HEADERS帧
            if frame_type == 1:  # HEADERS帧的类型为1
                logger.info("找到HEADERS帧")
                found_headers_frame = True
                
                # 提取帧数据
                frame_data = raw_data[offset+9:offset+9+frame_len]
                
                # 将帧数据转换为十六进制，便于查看
                logger.info("HEADERS帧内容:")
                logger.info(hexdump(frame_data))
                
                # 检查server:SMF字段
                server_pattern = re.compile(b'server.{0,10}SMF', re.IGNORECASE)
                if server_pattern.search(frame_data):
                    logger.info("✅ 找到server:SMF字段")
                else:
                    logger.warning("⚠️ 未找到server:SMF字段")
                
                # 检查content-length字段
                cl_pattern = re.compile(b'content-length.{0,10}[0-9]+', re.IGNORECASE)
                cl_match = cl_pattern.search(frame_data)
                if cl_match:
                    cl_str = cl_match.group(0)
                    logger.info(f"✅ 找到content-length字段: {cl_str}")
                else:
                    logger.warning("⚠️ 未找到content-length字段")
                
                # 尝试更准确地解析出值
                cl_digit_pattern = re.compile(b'content-length[: ]+([0-9]+)', re.IGNORECASE)
                cl_digit_match = cl_digit_pattern.search(frame_data)
                if cl_digit_match:
                    cl_value = cl_digit_match.group(1)
                    logger.info(f"Content-length值: {cl_value}")
            
            # 移到下一帧
            offset += 9 + frame_len
        
        if not found_headers_frame:
            logger.warning("未在第15号报文中找到HEADERS帧")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"处理PCAP文件时出错: {e}")
        logger.error(traceback.format_exc())
        return False

def main():
    """主函数"""
    # 检查参数
    if len(sys.argv) < 2:
        print("用法: python verify_pkt15.py <pcap文件路径>")
        return
    
    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(f"错误: 文件 {pcap_file} 不存在")
        return
    
    # 处理PCAP文件
    if process_pcap_file(pcap_file):
        print("验证完成，请查看日志获取详细信息")
    else:
        print("验证失败，请查看日志获取错误信息")

if __name__ == "__main__":
    main()
