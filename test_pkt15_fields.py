#!/usr/bin/env python3
# 测试第15号报文中的content-length和server:SMF字段是否被正确处理
# 这个脚本会手动创建一个HTTP/2报文，设置正确的字段，然后验证结果

from scapy.all import *
from scapy.layers.inet import IP, TCP
import logging
import sys
from hpack import Decoder, Encoder

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def create_test_packet():
    """创建一个测试用的HTTP/2报文"""
    # 创建HTTP/2 HEADERS帧
    encoder = Encoder()
    
    # 创建HTTP/2头部字段
    headers = [
        (b':status', b'201'),
        (b'server', b'SMF'),
        (b'content-length', b'351'),
        (b'content-type', b'application/json'),
        (b'date', b'Wed, 22 May 2025 04:30:00 GMT')
    ]
    
    # 使用HPACK编码头部
    encoded_headers = encoder.encode(headers)
    
    # 创建HTTP/2 HEADERS帧
    frame_type = 1  # 1 表示HEADERS帧
    frame_flags = 4  # 4 表示END_HEADERS标志
    stream_id = 1
    
    # 构造帧头
    frame_header = len(encoded_headers).to_bytes(3, byteorder='big')
    frame_header += bytes([frame_type])
    frame_header += bytes([frame_flags])
    frame_header += stream_id.to_bytes(4, byteorder='big')
    
    # 完整的HTTP/2帧
    http2_frame = frame_header + encoded_headers
    
    # 创建一个完整的IP/TCP报文
    ip = IP(src='30.0.0.1', dst='40.0.0.1')
    tcp = TCP(sport=12345, dport=80, flags='PA')
    pkt = ip/tcp/Raw(load=http2_frame)
    
    return pkt

def verify_fields(pkt):
    """验证报文中是否包含所需的字段"""
    if not pkt.haslayer(Raw):
        logger.error("报文没有负载")
        return False
    
    raw_data = pkt[Raw].load
    
    # 跳过帧头(9字节)
    frame_data = raw_data[9:]
    
    # 使用HPACK解码头部
    try:
        decoder = Decoder()
        headers = decoder.decode(frame_data)
        
        # 检查是否包含所需字段
        has_server = False
        has_content_length = False
        
        for name, value in headers:
            name_str = name.decode() if isinstance(name, bytes) else name
            value_str = value.decode() if isinstance(value, bytes) else value
            
            logger.info(f"头部字段: {name_str} = {value_str}")
            
            if name_str.lower() == 'server' and value_str == 'SMF':
                has_server = True
                logger.info("✅ 找到 server:SMF 字段")
            
            if name_str.lower() == 'content-length':
                has_content_length = True
                logger.info(f"✅ 找到 content-length 字段: {value_str}")
        
        if has_server and has_content_length:
            logger.info("✅ 报文中包含所有所需字段")
            return True
        else:
            if not has_server:
                logger.error("❌ 缺少 server:SMF 字段")
            if not has_content_length:
                logger.error("❌ 缺少 content-length 字段")
            return False
    
    except Exception as e:
        logger.error(f"解码头部时出错: {e}")
        return False

def main():
    """主函数"""
    logger.info("创建测试报文...")
    pkt = create_test_packet()
    
    logger.info("验证报文字段...")
    if verify_fields(pkt):
        logger.info("测试成功: 报文包含所有所需字段")
    else:
        logger.error("测试失败: 报文缺少必要字段")
    
    # 将报文保存到临时文件
    logger.info("保存测试报文...")
    wrpcap("test_pkt15.pcap", [pkt])
    logger.info("测试报文已保存到 test_pkt15.pcap")

if __name__ == "__main__":
    main()
