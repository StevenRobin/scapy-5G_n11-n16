"""
修复第15号报文处理问题
这个脚本直接创建一个新的完整文件，其中包含修正后的代码
"""
import os
import sys
print("开始执行修复脚本...")

# 读取原始文件
original_file = "h:/pythonProject/study_01/scapy-5G_n11-n16/n16_test_fixed02_1515.py"
fixed_file = "h:/pythonProject/study_01/scapy-5G_n11-n16/n16_test_fixed03.py"

print(f"正在读取原始文件: {original_file}")
if not os.path.exists(original_file):
    print(f"错误: 原始文件不存在: {original_file}")
    sys.exit(1)

try:
    with open(original_file, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"成功读取原始文件，大小: {len(content)} 字节")
except Exception as e:
    print(f"读取文件时出错: {e}")
    sys.exit(1)

# 查找第15号报文处理部分
print("正在查找第15号报文处理代码...")
pkt15_start = content.find("elif pkt_idx == 15:")
if pkt15_start >= 0:
    print(f"找到第15号报文处理开始位置: {pkt15_start}")
    # 找到下一个elif或else语句，作为结束点
    elif_pos = content.find("elif ", pkt15_start + 10)
    else_pos = content.find("else:", pkt15_start + 10)
    
    # 确定结束位置
    if elif_pos >= 0 and (else_pos < 0 or elif_pos < else_pos):
        pkt15_end = elif_pos
    elif else_pos >= 0:
        pkt15_end = else_pos
    else:
        # 如果找不到结束点，可能是最后一个条件，使用函数结束为边界
        end_markers = ["    except ", "    finally:", "    return ", "def "]
        pkt15_end = len(content)
        for marker in end_markers:
            pos = content.find(marker, pkt15_start + 10)
            if pos >= 0 and pos < pkt15_end:
                pkt15_end = pos
    
    print(f"找到第15号报文处理结束位置: {pkt15_end}")
    
    # 替换内容
    new_pkt15_code = '''elif pkt_idx == 15:
                logger.info("第15号报文 - 使用专门函数处理")
                # 直接处理第15号报文头部，确保保留所有必要头部字段
                try:
                    # 创建所需的头部字段
                    status_code = b"201 Created"
                    content_type = b"application/json"
                    new_location = f"http://{auth1}/nsmf-pdusession/v1/pdu-sessions/{context_ID}"
                    new_location_bytes = new_location.encode()
                    
                    # 构造标准HTTP/2头部
                    headers = [
                        (b':status', status_code),         # 状态码
                        (b'content-type', content_type),   # 内容类型 
                        (b'location', new_location_bytes), # 位置头部
                        (b'content-length', b'351'),       # 内容长度
                        (b'date', b'Wed, 22 May 2025 02:48:05 GMT')  # 日期
                    ]
                    
                    # 使用HPACK编码
                    encoder = Encoder()
                    headers_block = encoder.encode(headers)
                    
                    # 计算头部长度
                    header_length = len(headers_block)
                    
                    # 创建帧头 (9字节)
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
                    
                    # 查找原始DATA帧
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
                    # 如果处理失败，尝试使用原有方法
                    logger.warning("使用备用方法处理第15号报文")
'''
    
    print("正在替换处理代码...")
    # 生成修改后的内容
    updated_content = content[:pkt15_start] + new_pkt15_code + content[pkt15_end:]
    
    # 写入新文件
    try:
        with open(fixed_file, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        print(f"成功修复第15号报文处理代码！修复后的文件已保存为: {fixed_file}")
    except Exception as e:
        print(f"写入文件时出错: {e}")
else:
    print("未找到第15号报文处理代码，请检查文件内容。")
    
print("脚本执行完成。")
