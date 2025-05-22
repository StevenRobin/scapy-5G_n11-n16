#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
用于验证修复后的第15号数据包的HTTP头部是否符合要求
"""

from scapy.all import *
from hpack import Decoder
import logging
import sys
import os

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s',
    handlers=[
        logging.FileHandler("verify_pkt15_fixed.log", mode="w"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def verify_packet15_headers(pcap_file):
    """验证PCAP文件中第15号数据包的HTTP头部"""
    try:
        # 读取PCAP文件
        logger.info(f"读取PCAP文件: {pcap_file}")
        packets = rdpcap(pcap_file)
        
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
        logger.info(f"第15号数据包负载长度: {len(raw_payload)} 字节")
        
        # 找到HEADERS帧
        offset = 0
        headers_frame = None
        headers_data = None
        
        while offset < len(raw_payload) - 9:
            # 解析帧头
            frame_length = int.from_bytes(raw_payload[offset:offset+3], byteorder='big')
            frame_type = raw_payload[offset+3]
            
            # 确保帧长度有效
            if frame_length >= 0 and frame_length < 16384 and offset + 9 + frame_length <= len(raw_payload):
                # 找到HEADERS帧
                if frame_type == 1:  # HEADERS帧类型是1
                    headers_frame = raw_payload[offset:offset+9]
                    headers_data = raw_payload[offset+9:offset+9+frame_length]
                    logger.info(f"找到HEADERS帧, 长度: {frame_length}")
                    break
                
                # 移动到下一个帧
                offset += 9 + frame_length
            else:
                offset += 1
        
        if not headers_data:
            logger.error("未找到HEADERS帧")
            return False
        
        # 解码HEADERS帧
        decoder = Decoder()
        try:
            headers = decoder.decode(headers_data)
            logger.info("成功解码HEADERS帧")
            
            # 检查头部字段和顺序
            status_found = False
            location_found = False
            content_type_found = False
            content_length_found = False
            scheme_found = False
            
            # 检查头部顺序是否正确
            expected_order = [':status', 'location', 'content-type', 'content-length', 'date']
            actual_order = []
            
            for i, (name, value) in enumerate(headers):
                name_str = name.decode() if isinstance(name, bytes) else name
                value_str = value.decode() if isinstance(value, bytes) else value
                actual_order.append(name_str.lower())
                
                logger.info(f"  头部字段 {i+1}: {name_str}: {value_str}")
                
                if name_str.lower() == ':status':
                    status_found = True
                    # 检查状态码是否为"201"
                    if value_str != "201":
                        logger.error(f"状态码不正确: {value_str} (应为 '201')")
                        return False
                
                elif name_str.lower() == 'location':
                    location_found = True
                    # 检查location值是否正确
                    expected_location = "http://40.0.0.1/nsmf-pdusession/v1/pdu-sessions/9000000001"
                    if value_str != expected_location:
                        logger.error(f"Location值不正确: {value_str} (应为 {expected_location})")
                        return False
                
                elif name_str.lower() == 'content-type':
                    content_type_found = True
                    # 检查content-type值是否为"application/json"
                    if value_str != "application/json":
                        logger.error(f"Content-Type值不正确: {value_str} (应为 'application/json')")
                        return False
                
                elif name_str.lower() == 'content-length':
                    content_length_found = True
                    # 检查content-length值是否为"351"
                    if value_str != "351":
                        logger.error(f"Content-Length值不正确: {value_str} (应为 '351')")
                        return False
                
                elif name_str.lower() == ':scheme':
                    scheme_found = True
                    logger.error("发现不应该存在的:scheme字段")
                    return False
            
            # 检查所有必需的头部字段是否存在
            if not status_found:
                logger.error("缺少:status字段")
                return False
            if not location_found:
                logger.error("缺少location字段")
                return False
            if not content_type_found:
                logger.error("缺少content-type字段")
                return False
            if not content_length_found:
                logger.error("缺少content-length字段")
                return False
            
            # 检查头部顺序是否正确
            expected_order_lower = [x.lower() for x in expected_order]
            
            # 只比较前5个必需字段的顺序
            filtered_actual_order = [x for x in actual_order if x in expected_order_lower]
            
            if expected_order_lower != filtered_actual_order[:len(expected_order_lower)]:
                logger.error(f"头部字段顺序不正确: {filtered_actual_order} (应为 {expected_order_lower})")
                return False
            
            logger.info("所有头部字段验证通过!")
            return True
            
        except Exception as e:
            logger.error(f"解码HEADERS帧时出错: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
        
    except Exception as e:
        logger.error(f"验证第15号数据包时出错: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    print("开始执行验证脚本...")
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = "pcap/N16_fixed_pkt15_final.pcap"
    
    print(f"验证PCAP文件: {pcap_file}")
    
    if not os.path.exists(pcap_file):
        print(f"错误: PCAP文件不存在: {pcap_file}")
        logger.error(f"PCAP文件不存在: {pcap_file}")
        sys.exit(1)
    
    # 验证第15个数据包
    result = verify_packet15_headers(pcap_file)
    
    if result:
        print("\n=== 验证结果 ===")
        print("✓ 验证成功: 第15号数据包的HTTP头部符合所有要求!")
        print("✓ :status 字段值为 '201'")
        print("✓ location 字段值为 'http://40.0.0.1/nsmf-pdusession/v1/pdu-sessions/9000000001'")
        print("✓ content-type 字段值为 'application/json'")
        print("✓ content-length 字段值为 '351'")
        print("✓ 头部字段顺序正确: :status -> location -> content-type -> content-length -> date")
        print("✓ 不存在 :scheme 字段")
        logger.info("验证成功: 第15号数据包的HTTP头部符合所有要求!")
    else:
        print("\n=== 验证结果 ===")
        print("✗ 验证失败: 第15号数据包的HTTP头部不符合要求!")
        print("请查看日志获取详细错误信息。")
        logger.error("验证失败: 第15号数据包的HTTP头部不符合要求!")
