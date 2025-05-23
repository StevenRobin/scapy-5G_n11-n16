# 临时修复版本的n16_test_fixed02.py
from scapy.all import *
from scapy.layers.inet import IP, TCP
import logging

# 设置基本日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def fix_pkt15_content_length(pcap_in, pcap_out):
    """
    专门修复第15个报文的content-length字段

    参数:
        pcap_in: 输入PCAP文件路径
        pcap_out: 输出PCAP文件路径
    """
    logger.info(f"开始处理文件 {pcap_in}")
    try:
        packets = rdpcap(pcap_in)
    except Exception as e:
        logger.error(f"读取PCAP文件失败: {e}")
        return False
    
    if len(packets) < 15:
        logger.error(f"PCAP文件中的报文数量不足，只有 {len(packets)} 个报文")
        return False
    
    # 获取第15个报文
    pkt15 = packets[14]  # 索引从0开始，所以第15个报文是index=14
    
    if not pkt15.haslayer(Raw):
        logger.error("第15个报文没有负载数据")
        return False
    
    # 提取原始负载
    raw = bytes(pkt15[Raw].load)
    logger.info(f"第15个报文原始负载长度: {len(raw)}")
    
    # 解析HTTP/2帧
    offset = 0
    modified = False
    
    while offset + 9 < len(raw):
        # 解析帧头
        frame_len = int.from_bytes(raw[offset:offset+3], byteorder='big')
        frame_type = raw[offset+3]
        frame_flags = raw[offset+4]
        stream_id = int.from_bytes(raw[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
        
        logger.info(f"帧类型: {frame_type}, 长度: {frame_len}, 标志: {frame_flags}, 流ID: {stream_id}")
        
        # 如果是HEADERS帧，尝试修改
        if frame_type == 1:  # HEADERS帧的类型为1
            logger.info("找到HEADERS帧")
            
            # 提取帧数据
            frame_data = raw[offset+9:offset+9+frame_len]
            
            # 尝试修改HEADERS帧内容
            try:
                from hpack import Decoder, Encoder
                
                # 解码现有头部
                decoder = Decoder()
                encoder = Encoder()
                
                try:
                    headers = decoder.decode(frame_data)
                    
                    # 查找现有的头部
                    new_headers = []
                    has_server = False
                    cl_removed = False
                    content_length_value = None
                    
                    for name, value in headers:
                        name_str = name.decode() if isinstance(name, bytes) else name
                        value_str = value.decode() if isinstance(value, bytes) else value
                        
                        logger.info(f"头部字段: {name_str} = {value_str}")
                        
                        # 检查server字段
                        if name_str.lower() == 'server':
                            has_server = True
                            logger.info(f"找到server字段: {value_str}")
                        
                        # 检查content-length字段
                        is_content_length = name_str.lower() == "content-length"
                        if is_content_length:
                            cl_removed = True
                            content_length_value = value_str
                            logger.info(f"找到content-length字段: {value_str}")
                        
                        # 保留所有头部字段
                        new_headers.append((name, value))
                    
                    # 如果没有server字段，添加一个
                    if not has_server:
                        logger.info("添加缺失的server:SMF字段")
                        new_headers.append((b'server', b'SMF'))
                        modified = True
                    
                    # 如果没有content-length字段，添加一个默认值
                    if not cl_removed:
                        logger.info("添加缺失的content-length字段")
                        new_headers.append((b'content-length', b'351'))
                        modified = True
                    
                    # 重新编码头部
                    new_frame_data = encoder.encode(new_headers)
                    
                    # 更新帧
                    if modified:
                        # 构建新的帧
                        new_frame_len = len(new_frame_data)
                        new_frame_header = new_frame_len.to_bytes(3, byteorder='big')
                        new_frame_header += bytes([frame_type])
                        new_frame_header += bytes([frame_flags])
                        new_frame_header += (stream_id & 0x7FFFFFFF).to_bytes(4, byteorder='big')
                        
                        # 替换原始帧
                        raw = raw[:offset] + new_frame_header + new_frame_data + raw[offset+9+frame_len:]
                        
                        logger.info(f"更新了HEADERS帧，新长度: {new_frame_len}")
                        
                        # 由于帧长度可能改变，需要重新计算下一个偏移量
                        offset += 9 + new_frame_len
                    else:
                        # 没有修改，继续到下一帧
                        offset += 9 + frame_len
                
                except Exception as e:
                    logger.warning(f"解码HEADERS帧失败: {e}")
                    offset += 9 + frame_len
            
            except Exception as e:
                logger.warning(f"处理HEADERS帧时出错: {e}")
                offset += 9 + frame_len
        
        else:
            # 非HEADERS帧，跳过处理
            offset += 9 + frame_len
    
    # 如果进行了修改，更新报文
    if modified:
        pkt15[Raw].load = raw
        logger.info(f"更新报文负载，新长度: {len(raw)}")
        
        # 重新计算校验和
        del pkt15[IP].len
        del pkt15[IP].chksum
        if pkt15.haslayer(TCP):
            del pkt15[TCP].chksum
        
        # 保存修改后的PCAP
        wrpcap(pcap_out, packets)
        logger.info(f"保存修改后的PCAP到 {pcap_out}")
        return True
    else:
        logger.warning("未对报文进行任何修改")
        return False

def main():
    """主处理流程"""
    # 解析命令行参数
    import argparse
    parser = argparse.ArgumentParser(description='处理N16 PCAP文件中的HTTP/2帧')
    parser.add_argument('-i', '--input', dest='input_file', required=True,
                       help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', required=True,
                       help='输出PCAP文件路径')
    
    args = parser.parse_args()
    
    # 处理PCAP文件
    success = fix_pkt15_content_length(args.input_file, args.output_file)
    
    if success:
        print("处理成功！")
    else:
        print("处理失败，请查看日志获取详细信息。")

if __name__ == "__main__":
    main()
