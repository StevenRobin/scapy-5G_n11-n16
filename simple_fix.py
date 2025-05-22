"""
简单直接地修复第15号报文头部问题
"""

import os
import sys
from shutil import copy2

# 文件路径
original_file = "h:/pythonProject/study_01/scapy-5G_n11-n16/n16_test_fixed02_1515.py"
target_file = "h:/pythonProject/study_01/scapy-5G_n11-n16/n16_test_fixed_pkt15.py"

# 首先备份原始文件
print(f"备份原始文件到: {target_file}")
try:
    copy2(original_file, target_file)
    print(f"备份成功")
except Exception as e:
    print(f"备份文件失败: {e}")
    sys.exit(1)

# 要插入的新函数代码
pkt15_function = '''
def process_packet15(frame_data):
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
'''

# 要修改的第15号报文处理部分代码
pkt15_handler = '''
            # 第15号报文使用专门函数处理
            elif pkt_idx == 15:
                logger.info("第15号报文 - 使用专门函数处理")
                return process_packet15(frame_data)
'''

# 读取文件内容
print(f"读取文件: {target_file}")
try:
    with open(target_file, 'r', encoding='utf-8') as f:
        content = f.read()
    print("文件读取成功")
except Exception as e:
    print(f"读取文件失败: {e}")
    sys.exit(1)

# 查找函数插入位置 - 在process_special_headers函数之前
print("查找函数插入位置...")
func_pos = content.find("def process_special_headers")
if func_pos == -1:
    print("错误: 未找到process_special_headers函数")
    sys.exit(1)

# 查找process_special_headers函数中处理第15号报文的代码块
print("查找第15号报文处理代码...")
pkt15_pos = content.find("elif pkt_idx == 15:", func_pos)
if pkt15_pos == -1:
    print("错误: 未找到第15号报文处理代码")
    sys.exit(1)

# 找到下一个处理分支的位置作为结束点
pkt_next = content.find("elif pkt_idx", pkt15_pos + 10)
if pkt_next == -1:
    pkt_next = content.find("else:", pkt15_pos + 10)
if pkt_next == -1:
    pkt_next = content.find("        # 对于其他报文", pkt15_pos + 10)

if pkt_next == -1:
    print("警告: 未找到第15号报文处理代码块的结束位置，可能无法正确替换")
    # 在这种情况下，搜索可能的结束点标记
    end_markers = ["    except", "    finally", "def ", "return"]
    for marker in end_markers:
        pos = content.find(marker, pkt15_pos + 20)
        if pos != -1:
            pkt_next = pos
            print(f"使用备用标记'{marker}'作为结束位置: {pos}")
            break

if pkt_next == -1:
    print("错误: 无法确定第15号报文处理代码块的结束位置")
    sys.exit(1)

# 插入新函数和替换处理代码
print("修改文件内容...")
modified_content = (
    content[:func_pos] + 
    pkt15_function + 
    content[func_pos:pkt15_pos] + 
    pkt15_handler + 
    content[pkt_next:]
)

# 写入修改后的文件
print(f"写入修改后的文件: {target_file}")
try:
    with open(target_file, 'w', encoding='utf-8') as f:
        f.write(modified_content)
    print("文件成功修改！")
except Exception as e:
    print(f"写入文件失败: {e}")
    sys.exit(1)

print("修复完成，新文件包含专门处理第15号报文的函数，确保保留所有头部字段。")
