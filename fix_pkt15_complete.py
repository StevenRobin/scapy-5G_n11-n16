#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
此脚本专门用于修复第15号数据包中的HTTP头部问题：
1. :status 字段值长度为3，值为"201"（不是"201 Created"）
2. 删除 :scheme: http 字段
3. 添加 content-length: 351 字段
4. 确保Location字段值为 http://40.0.0.1/nsmf-pdusession/v1/pdu-sessions/9000000001
5. 确保头部字段顺序为: :status -> location -> content-type -> content-length -> date
"""

from scapy.all import *
from hpack import Encoder
import logging
import sys
import os
import re
import argparse

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s',
    handlers=[
        logging.FileHandler("fix_pkt15_complete.log", mode="w"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def fix_packet15_headers(input_pcap, output_pcap):
    """专门用于修复PCAP文件中的第15号数据包的HTTP头部"""
    try:
        # 读取PCAP文件
        logger.info(f"读取PCAP文件: {input_pcap}")
        packets = rdpcap(input_pcap)
        
        # 检查PCAP文件是否至少包含15个数据包
        if len(packets) < 15:
            logger.error(f"PCAP文件中数据包数量不足: {len(packets)}")
            return False
        
        # 获取第15个数据包 (索引从1开始，所以第15个包是索引14)
        pkt15 = packets[14]
        
        # 确保包含TCP和Raw层
        if not (pkt15.haslayer(TCP) and pkt15.haslayer(Raw)):
            logger.error("第15个数据包不包含TCP或Raw层")
            return False
        
        # 获取原始负载
        raw_payload = bytes(pkt15[Raw].load)
        logger.info(f"第15号数据包原始负载长度: {len(raw_payload)} 字节")
        
        # 创建新的HTTP/2头部
        
        # 1. 设置正确的头部字段 - 严格按照要求的顺序
        status_code = b"201"  # 注意值仅为201，不包含"Created"
        content_type = b"application/json"
        location = b"http://40.0.0.1/nsmf-pdusession/v1/pdu-sessions/9000000001"
        
        # 2. 按顺序构造HTTP/2头部
        headers = [
            (b':status', status_code),                 # 状态码，值仅为"201"
            (b'location', location),                   # 位置URL，使用固定值
            (b'content-type', content_type),           # 内容类型
            (b'content-length', b'351'),               # 内容长度
            (b'date', b'Wed, 22 May 2025 02:48:05 GMT')  # 日期
        ]
        
        # 3. 对头部使用HPACK编码
        encoder = Encoder()
        headers_block = encoder.encode(headers)
        
        # 4. 计算头部长度
        header_length = len(headers_block)
        
        # 5. 创建HTTP/2 HEADERS帧头部
        frame_type = 1    # HEADERS帧
        flags = 4         # END_HEADERS
        stream_id = 1     # 流ID=1
        
        header_frame = (
            header_length.to_bytes(3, byteorder='big') +  # 长度 (3字节)
            bytes([frame_type]) +                         # 类型 (1字节)
            bytes([flags]) +                              # 标志 (1字节)
            bytes([0, 0, 0, stream_id])                   # 保留位(1位) + 流ID(31位) = 4字节
        )
        
        # 6. 查找原始DATA帧
        offset = 0
        data_frame = None
        
        while offset < len(raw_payload) - 9:
            try:
                # 解析帧头
                frame_length = int.from_bytes(raw_payload[offset:offset+3], byteorder='big')
                frame_type_value = raw_payload[offset+3]
                
                # 确保帧长度有效
                if frame_length >= 0 and frame_length < 16384 and offset + 9 + frame_length <= len(raw_payload):
                    # 找到DATA帧
                    if frame_type_value == 0:  # DATA帧类型是0
                        data_frame = raw_payload[offset:offset+9+frame_length]
                        logger.info(f"找到DATA帧, 长度: {frame_length}")
                        break
                    
                    # 移动到下一个帧
                    offset += 9 + frame_length
                else:
                    offset += 1
            except Exception as e:
                logger.error(f"解析帧出错: {e}")
                offset += 1
        
        # 7. 如果没有找到DATA帧，使用默认的DATA帧
        if data_frame is None:
            logger.warning("未找到DATA帧，使用默认DATA帧")
            data_frame = bytes.fromhex(
                "00000159" +  # 长度 (345字节)
                "00" +        # 类型 (DATA)
                "01" +        # 标志 (END_STREAM)
                "00000001" +  # 流ID
                # 使用有效的JSON作为负载
                "7b2273757069223a22696d73692d34363030313233303030303030303031222c2270656922"
                "3a22696d656973762d38363131313031303030303030303131222c2267707369223a226d73"
                "6973646e2d38363133393030303030303031222c2270647553657373696f6e4964223a2231"
                "30303030303031222c22646e6e223a22646e6e363030303030303031222c22734e73736169"
                "223a7b22737374223a312c227364223a22303130323033227d2c2276736d664964223a2234"
                "302e302e302e31222c2269736d664964223a22303030353030303030303031222c2263704"
                "36e54756e6e656c496e666f223a7b2269707634416464722223a2232302e302e302e31222"
                "c226774705465696423a2235303030303030317d7d"
            )
        
        # 8. 组合新的HEADERS和原来的DATA帧
        new_payload = header_frame + headers_block + data_frame
        
        # 9. 更新第15个数据包的负载
        pkt15[Raw].load = new_payload
        logger.info(f"更新后的负载长度: {len(new_payload)} 字节")
        
        # 10. 重新计算校验和
        if hasattr(pkt15[IP], 'chksum'):
            del pkt15[IP].chksum
        if hasattr(pkt15[TCP], 'chksum'):
            del pkt15[TCP].chksum
        
        # 11. 保存修改后的PCAP
        wrpcap(output_pcap, packets)
        
        logger.info(f"成功修复第15个数据包的HTTP头部:")
        logger.info(f"  :status: {status_code.decode()}")
        logger.info(f"  Location: {location.decode()}")
        logger.info(f"  Content-Type: {content_type.decode()}")
        logger.info(f"  Content-Length: 351")
        logger.info(f"  头部字段顺序已确认: :status -> location -> content-type -> content-length -> date")
        logger.info(f"修改后的PCAP已保存为: {output_pcap}")
        
        return True
    
    except Exception as e:
        logger.error(f"修复第15号数据包时出错: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    # 添加调试信息到控制台
    print("开始执行fix_pkt15_complete.py脚本")
    print(f"当前工作目录: {os.getcwd()}")
    
    # 命令行参数解析
    parser = argparse.ArgumentParser(description='修复PCAP文件中第15号数据包的HTTP头部')
    parser.add_argument('-i', '--input', dest='input_file', default="pcap/N16_create_16p.pcap",
                        help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', default="pcap/N16_fixed_pkt15.pcap",
                        help='输出PCAP文件路径')
    
    args = parser.parse_args()
    print(f"输入文件: {args.input_file}")
    print(f"输出文件: {args.output_file}")
    
    # 检查输入文件是否存在
    if not os.path.exists(args.input_file):
        print(f"错误: 输入文件不存在: {args.input_file}")
        logger.error(f"输入文件不存在: {args.input_file}")
        sys.exit(1)
    
    # 确保输出目录存在
    output_dir = os.path.dirname(args.output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 修复第15个数据包
    if fix_packet15_headers(args.input_file, args.output_file):
        logger.info(f"修复成功! 结果已保存至: {args.output_file}")
    else:
        logger.error("修复失败，请检查日志获取详细信息。")
