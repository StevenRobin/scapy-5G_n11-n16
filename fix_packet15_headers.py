# 修复第15号报文头部处理问题
# 该脚本将为n16_test_fixed02_1515.py添加一个专门处理第15号报文头部的函数

import sys
import os
import re
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def insert_code(file_path):
    """向主文件中插入处理第15号报文头部的专门函数"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 查找插入点 - 找到process_special_headers函数
        match = re.search(r'def process_special_headers\(frame_data, pkt_idx\):', content)
        if not match:
            logger.error("未找到process_special_headers函数，无法插入代码")
            return False
        
        # 准备要插入的专门函数
        new_function = """
def process_packet15_headers(frame_data):
    """专门处理第15号报文的HTTP/2头部，确保保留所有必需的头部字段"""
    try:
        logger.info("使用专门的函数处理第15号报文头部")
        
        # 创建我们需要的所有头部字段
        status_code = b"201 Created"
        content_type = b"application/json"
        new_location = f"http://{auth1}/nsmf-pdusession/v1/pdu-sessions/{context_ID}"
        new_location_bytes = new_location.encode()
        
        # 构造标准HTTP/2头部帧
        headers = [
            (b':status', status_code),  # 状态码
            (b'content-type', content_type),  # 内容类型
            (b'location', new_location_bytes),  # 位置头部
            (b'content-length', b'351'),  # 内容长度
            (b'date', b'Wed, 22 May 2025 02:48:05 GMT')  # 日期
        ]
        
        # 使用HPACK编码器对头部进行编码
        from hpack import Encoder
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
        
        # 查找原始DATA帧 - 我们需要保留原始数据部分
        data_frame = None
        offset = 0
        
        while offset < len(frame_data) - 9:  # 9字节是帧头长度
            try:
                # 解析帧头
                frame_length = int.from_bytes(frame_data[offset:offset+3], byteorder='big')
                frame_type_value = frame_data[offset+3]
                
                # 检查帧是否有效
                if frame_length >= 0 and frame_length < 16384 and offset + 9 + frame_length <= len(frame_data):
                    # 如果是DATA帧
                    if frame_type_value == 0:  # DATA帧类型是0
                        data_frame = frame_data[offset:offset+9+frame_length]
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
                # DATA负载内容 (JSON格式) - 从原始报文中提取
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
        
        # 组合HEADERS和DATA帧
        new_frame_data = header_frame + headers_block + data_frame
        
        # 记录处理结果
        logger.info("成功创建第15号报文头部，包含所有必需字段:")
        logger.info(f"  :status: {status_code.decode()}")
        logger.info(f"  Content-Type: {content_type.decode()}")
        logger.info(f"  Location: {new_location}")
        logger.info(f"  Content-Length: 351")
        logger.info(f"  新帧总长度: {len(new_frame_data)} 字节")
        
        return new_frame_data
    
    except Exception as e:
        logger.error(f"处理第15号报文头部时出错: {e}")
        import traceback
        logger.error(traceback.format_exc())
        # 返回原始数据，避免处理失败
        return frame_data

"""
        
        # 查找process_special_headers函数中处理第15号报文的部分
        pkt15_match = re.search(r'elif\s+pkt_idx\s*==\s*15\s*:', content)
        if pkt15_match:
            # 在process_special_headers函数之前插入新函数
            insert_pos = match.start()
            modified_content = content[:insert_pos] + new_function + content[insert_pos:]
            
            # 修改process_special_headers函数中处理第15号报文的部分，直接调用新函数
            pkt15_block_start = pkt15_match.start()
            pkt15_block_end_match = re.search(r'(?:elif\s+pkt_idx|else)(?!\s*==\s*15)', content[pkt15_block_start:])
            
            if pkt15_block_end_match:
                pkt15_block_end = pkt15_block_start + pkt15_block_end_match.start()
                
                # 构建新的第15号报文处理块
                new_pkt15_block = """elif pkt_idx == 15:
                logger.info("第15号报文 - 使用专门函数处理")
                return process_packet15_headers(frame_data)
                
                """
                
                # 替换旧的处理块
                modified_content = modified_content[:pkt15_block_start] + new_pkt15_block + modified_content[pkt15_block_end:]
            else:
                logger.warning("未找到第15号报文处理块的结束点，跳过修改处理块")
        
        # 写入修改后的内容
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(modified_content)
        
        logger.info(f"成功向{file_path}插入process_packet15_headers函数")
        return True
        
    except Exception as e:
        logger.error(f"修改文件时出错: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = "h:/pythonProject/study_01/scapy-5G_n11-n16/n16_test_fixed02_1515.py"
    
    if not os.path.exists(file_path):
        logger.error(f"文件不存在: {file_path}")
        sys.exit(1)
    
    success = insert_code(file_path)
    if success:
        print(f"成功修复第15号报文头部处理。修改已保存到: {file_path}")
    else:
        print("修复失败，请查看日志了解详情。")
