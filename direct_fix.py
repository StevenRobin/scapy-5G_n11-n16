# 高级修复脚本 - 修复第15号报文头部处理问题
import sys

# 主要文件路径
file_path = "h:/pythonProject/study_01/scapy-5G_n11-n16/n16_test_fixed02_1515.py"

# 读取文件内容
with open(file_path, 'r', encoding='utf-8') as file:
    content = file.read()

# 专门处理第15号报文的函数
new_function = '''
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
'''

# 修改process_special_headers函数中处理第15号报文的部分
new_process_special_headers = '''
def process_special_headers(frame_data, pkt_idx):
    """特殊处理HTTP2 Headers帧"""
    try:
        # 日志确认正在处理哪个报文
        logger.info(f"开始处理第{pkt_idx}号报文的HTTP/2头部")

        # 定义二进制搜索替换辅助函数 - 在整个函数中通用
        def binary_replace(data, search_pattern, replace_pattern):
            if search_pattern in data:
                logger.debug(f"找到模式: {search_pattern}")
                return data.replace(search_pattern, replace_pattern)
            return data  # 返回原数据，而不是None，这样可以链式调用
            
        # 第9、11、13、15号报文使用二进制替换方法，因为它们的头部可能无法由标准hpack正确解析
        if pkt_idx in {9, 11, 13, 15}:
            logger.info(f"对第{pkt_idx}个报文使用混合处理方法 - 先尝试HPACK方法，如果失败则使用二进制方法")
                
            # 第13号报文特殊处理 - 保留content-type并正确设置authority
            if pkt_idx == 13:
                logger.info(f"特殊处理第{pkt_idx}号报文 - 确保content-type存在且头部正确")
                # 保存原始content-type
                content_type = None
                content_type_patterns = [
                    b'content-type: ', 
                    b'Content-Type: ', 
                    b'content-type:', 
                    b'Content-Type:'
                ]
                for pattern in content_type_patterns:
                    type_pos = frame_data.find(pattern)
                    if type_pos >= 0:
                        val_start = type_pos + len(pattern)
                        val_end = -1
                        for end_mark in [b'\\r\\n', b'\\n', b';']:
                            pos = frame_data.find(end_mark, val_start)
                            if pos > 0 and (val_end < 0 or pos < val_end):
                                val_end = pos
                        if val_end > val_start:
                            content_type = frame_data[val_start:val_end]
                            logger.info(f"保留原有content-type: {content_type}")
                            break
                
                # 构造一个最小化的、正确的头部集
                minimal_headers = [
                    (b':method', b'POST'),
                    (b':scheme', b'http'),
                    (b':authority', auth1.encode()),
                    (b':path', b'/nsmf-pdusession/v1/pdu-sessions')
                ]
                
                # 如果原来有content-type，添加它
                if content_type:
                    minimal_headers.append((b'content-type', content_type))
                else:
                    # 默认添加application/json
                    minimal_headers.append((b'content-type', b'application/json'))
                    logger.info("添加默认content-type: application/json")
                
                # 添加可能有用的其他常见header
                accept_header = None
                for accept_pattern in [b'accept:', b'Accept:', b'accept: ', b'Accept: ']:
                    accept_pos = frame_data.find(accept_pattern)
                    if accept_pos >= 0:
                        val_start = accept_pos + len(accept_pattern)
                        val_end = -1
                        for end_mark in [b'\\r\\n', b'\\n', b';']:
                            pos = frame_data.find(end_mark, val_start)
                            if pos > 0 and (val_end < 0 or pos < val_end):
                                val_end = pos
                        if val_end > val_start:
                            accept_header = frame_data[val_start:val_end]
                            minimal_headers.append((b'accept', accept_header))
                            logger.info(f"添加accept头: {accept_header}")
                            break
                
                # 编码这些最小化的头部
                encoder = Encoder()
                new_data = encoder.encode(minimal_headers)
                logger.info(f"为第13号报文创建了最小化头部，新长度: {len(new_data)}")
                return new_data
                
            # 第15号报文使用专门函数处理
            elif pkt_idx == 15:
                logger.info("第15号报文 - 使用专门函数处理")
                return process_packet15_headers(frame_data)
'''

# 查找pattern
original_function_def = 'def process_special_headers(frame_data, pkt_idx):'

# 在文件中插入新函数
if original_function_def in content:
    # 在函数定义前插入新函数
    function_pos = content.find(original_function_def)
    updated_content = content[:function_pos] + new_function + "\n" + content[function_pos:]
    
    # 替换原始函数实现
    updated_content = updated_content.replace(original_function_def, new_process_special_headers)
    
    # 写回文件
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(updated_content)
    
    print(f"成功向{file_path}添加process_packet15_headers函数并更新process_special_headers函数！")
else:
    print("未找到process_special_headers函数，请检查文件内容。")
