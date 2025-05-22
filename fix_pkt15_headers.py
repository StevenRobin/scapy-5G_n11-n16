"""
专门用于修复第15号报文头部字段丢失问题的独立脚本
这个脚本创建一个函数，在处理第15号报文时直接生成正确的所有头部字段
"""

from scapy.all import *
from hpack import Encoder
import logging
import sys
import os

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fix_pkt15.log", mode="w"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 定义重要变量
auth1 = "40.0.0.1"  # HTTP2 authority
context_ID = "9000000001"  # HTTP2 path中的context_ID

def fix_packet15_headers(input_pcap, output_pcap):
    """
    修复PCAP文件中第15号报文的HTTP/2头部，确保它包含所有必要的头部字段
    """
    logger.info(f"开始处理PCAP文件: {input_pcap}")
    logger.info(f"将保存修复后的结果到: {output_pcap}")
    
    # 读取PCAP文件
    packets = rdpcap(input_pcap)
    logger.info(f"成功读取 {len(packets)} 个报文")
    
    # 找到第15号报文
    if len(packets) < 15:
        logger.error(f"PCAP文件中报文数量不足 ({len(packets)})")
        return False
    
    # 获取第15个报文 (索引从0开始，所以是第14个)
    pkt15 = packets[14]
    
    # 检查是否包含TCP层并提取负载
    if not pkt15.haslayer(TCP) or not pkt15.haslayer(Raw):
        logger.error("第15号报文不包含TCP层或Raw数据")
        return False
    
    # 提取原始负载
    original_payload = bytes(pkt15[Raw].load)
    logger.info(f"提取到第15号报文的原始负载，大小: {len(original_payload)} 字节")
    
    # 创建新的HTTP/2头部
    status_code = b"201 Created"
    content_type = b"application/json"
    new_location = f"http://{auth1}/nsmf-pdusession/v1/pdu-sessions/{context_ID}"
    new_location_bytes = new_location.encode()
    
    # 构造HTTP/2头部字段列表
    headers = [
        (b':status', status_code),           # 状态码
        (b'content-type', content_type),     # 内容类型
        (b'location', new_location_bytes),   # 位置头部
        (b'content-length', b'351'),         # 内容长度
        (b'date', b'Wed, 22 May 2025 02:48:05 GMT')  # 日期
    ]
    
    # 使用HPACK编码器编码头部
    encoder = Encoder()
    headers_block = encoder.encode(headers)
    
    # 计算头部长度
    header_length = len(headers_block)
    
    # 创建HTTP/2帧头 (9字节)
    frame_type = 1  # HEADERS帧
    flags = 4       # END_HEADERS
    stream_id = 1   # 流ID=1
    
    # 组装帧头
    header_frame = (
        header_length.to_bytes(3, byteorder='big') +  # 长度 (3字节)
        bytes([frame_type]) +                         # 类型 (1字节)
        bytes([flags]) +                              # 标志 (1字节)
        bytes([0, 0, 0, stream_id])                   # 保留位(1位) + 流ID(31位) = 4字节
    )
    
    # 在原始负载中查找DATA帧
    data_frame = None
    offset = 0
    
    while offset < len(original_payload) - 9:  # 9字节是帧头长度
        try:
            # 解析帧头
            frame_length = int.from_bytes(original_payload[offset:offset+3], byteorder='big')
            frame_type_value = original_payload[offset+3]
            
            # 检查帧是否有效
            if frame_length >= 0 and frame_length < 16384 and offset + 9 + frame_length <= len(original_payload):
                # 如果是DATA帧
                if frame_type_value == 0:  # DATA帧类型是0
                    data_frame = original_payload[offset:offset+9+frame_length]
                    logger.info(f"找到DATA帧, 长度: {frame_length}")
                    break
                # 跳到下一帧
                offset += 9 + frame_length
            else:
                # 无效帧，前进一个字节继续查找
                offset += 1
        except Exception as e:
            logger.error(f"解析帧时出错: {e}")
            offset += 1
    
    # 如果找不到DATA帧，提供默认的DATA帧
    if data_frame is None:
        logger.warning("未找到有效的DATA帧，使用默认DATA帧")
        # 默认的DATA帧，包含合适的长度和JSON数据
        data_frame = bytes.fromhex(
            "00000159" +  # 长度 (345字节)
            "00" +        # 类型 (DATA帧)
            "00" +        # 标志
            "00000001" +  # 流ID
            # DATA负载内容 (JSON格式)
            "7b2274797065223a2243524541544544" +
            "5f5241535345535349" +
            "4f4e5f4143434550542c20585858222c2267707369223a226d" +
            "7369736e646e2d3836313339303030303030303012222c2273" +
            "75626a656374223a7b227375627363726962657273223a7b22" +
            "696d7369223a2234363030373232303030313030303122227d" +
            "7d2c2275654970763441646472657373223a223130302e302e" +
            "302e31222c226e656564532d6e7373616922747275652c226e" +
            "65656432417574686e223a66616c73652c22646e6e223a2264" +
            "6e6e36303030303030303122"
        )
    
    # 组合HEADERS和DATA帧创建新的HTTP/2负载
    new_payload = header_frame + headers_block + data_frame
    
    # 记录处理结果
    logger.info("成功创建第15号报文头部，包含所有必需字段:")
    logger.info(f"  :status: {status_code.decode()}")
    logger.info(f"  Content-Type: {content_type.decode()}")
    logger.info(f"  Location: {new_location}")
    logger.info(f"  Content-Length: 351")
    logger.info(f"  新负载长度: {len(new_payload)} 字节")
    
    # 替换第15号报文的负载
    pkt15[Raw].load = new_payload
    
    # 重新计算检验和
    if pkt15.haslayer(IP):
        del pkt15[IP].chksum
    if pkt15.haslayer(TCP):
        del pkt15[TCP].chksum
    
    # 保存修改后的PCAP文件
    wrpcap(output_pcap, packets)
    logger.info(f"成功保存修改后的PCAP文件: {output_pcap}")
    
    return True

if __name__ == "__main__":
    # 设置默认的输入和输出文件路径
    default_input = "h:/pythonProject/study_01/scapy-5G_n11-n16/pcap/N16_fixed_v3.pcap"
    default_output = "h:/pythonProject/study_01/scapy-5G_n11-n16/pcap/N16_fixed_pkt15_headers.pcap"
    
    # 设置输入和输出文件路径
    if len(sys.argv) > 2:
        input_pcap = sys.argv[1]
        output_pcap = sys.argv[2]
    elif len(sys.argv) == 2:
        input_pcap = sys.argv[1]
        output_pcap = default_output
    else:
        print(f"使用默认输入文件: {default_input}")
        print(f"使用默认输出文件: {default_output}")
        input_pcap = default_input
        output_pcap = default_output
    
    # 检查输入文件是否存在
    if not os.path.exists(input_pcap):
        print(f"错误: 输入文件不存在: {input_pcap}")
        sys.exit(1)
    
    # 确保输出目录存在
    output_dir = os.path.dirname(output_pcap)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"创建输出目录: {output_dir}")
        except Exception as e:
            print(f"创建输出目录失败: {e}")
    
    # 执行修复
    print(f"正在处理输入文件: {input_pcap}")
    print(f"输出将保存到: {output_pcap}")
    success = fix_packet15_headers(input_pcap, output_pcap)
    
    if success:
        print(f"成功修复第15号报文头部，已保存到: {output_pcap}")
    else:
        print("修复失败，请查看日志了解详情。")
