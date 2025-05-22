from scapy.all import *
from scapy.layers.inet import IP, TCP
import logging
import re
import traceback
import os
import argparse
from hpack import Decoder, Encoder
import sys

# 配置日志记录器
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fix_pkt15.log", mode="w"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def apply_fix_to_file(filepath):
    """
    修复n16_test_fixed02.py文件中处理第15号报文content-length的问题
    """
    # 读取原文件
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # 查找需要替换的部分 - 关键是修改"过滤掉所有content-length字段"的逻辑
    pattern1 = r"""                                            for name, value in headers:
                                                name_str = name.decode\(\) if isinstance\(name, bytes\) else name
                                                # 过滤掉所有content-length字段
                                                is_content_length = isinstance\(name_str, str\) and name_str\.lower\(\) == "content-length"
                                                if is_content_length:
                                                    cl_removed = True
                                                    continue
                                                new_headers\.append\(\(name, value\)\)"""
    
    replacement1 = """                                            for name, value in headers:
                                                name_str = name.decode() if isinstance(name, bytes) else name
                                                # 保留content-length字段，但记录下来以便稍后可能需要更新
                                                is_content_length = isinstance(name_str, str) and name_str.lower() == "content-length"
                                                if is_content_length:
                                                    cl_removed = True
                                                    # 保留原始content-length
                                                    new_headers.append((name, value))
                                                    logger.info(f"第15号报文：保留content-length值: {value}")
                                                else:
                                                    new_headers.append((name, value))"""
    
    # 执行替换
    new_content = re.sub(pattern1, replacement1, content)
    
    # 查找第二个需要替换的部分 - 修改紧急恢复中添加content-length的逻辑
    pattern2 = r"""                        # 添加Content-Length如果存在
                        if original_content_length:
                            emergency_headers\.append\(\(b'content-length', str\(original_content_length\)\.encode\(\)\)\)
                        else:
                            emergency_headers\.append\(\(b'content-length', b'351'\)\)  # 默认值"""
    
    replacement2 = """                        # 添加Content-Length如果存在
                        if original_content_length:
                            emergency_headers.append((b'content-length', str(original_content_length).encode()))
                            logger.info(f"添加原始content-length值到紧急头部: {original_content_length}")
                        else:
                            emergency_headers.append((b'content-length', b'351'))  # 默认值
                            logger.info(f"添加默认content-length值(351)到紧急头部")"""
    
    # 执行第二个替换
    new_content = re.sub(pattern2, replacement2, new_content)

    # 添加第三处替换，确保在HPACK处理后的content-length不被移除
    pattern3 = r"""                                            if not has_server:
                                                logger\.info\("第15号报文：添加缺失的server字段"\)
                                                new_headers\.append\(\(b'server', b'SMF'\)\)"""
    
    replacement3 = """                                            if not has_server:
                                                logger.info("第15号报文：添加缺失的server字段")
                                                new_headers.append((b'server', b'SMF'))
                                            
                                            # 如果没有content-length字段，添加一个
                                            if not cl_removed:
                                                logger.info("第15号报文：添加缺失的content-length字段")
                                                new_headers.append((b'content-length', b'351'))"""
    
    # 执行第三个替换
    new_content = re.sub(pattern3, replacement3, new_content)
    
    # 写入修改后的内容
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"已成功应用修复到文件: {filepath}")
    logger.info(f"已成功应用修复到文件: {filepath}")
    return True

def remove_content_length_headers(headers_data):
    """移除所有现有的content-length字段"""
    try:
        # 首先尝试二进制方式移除
        modified_data = headers_data
        content_removed = False
        
        # 查找所有可能的content-length字段
        for cl_pattern in [b'content-length:', b'content-length: ', b'Content-Length:', b'Content-Length: ']:
            pattern_pos = modified_data.lower().find(cl_pattern.lower())
            while pattern_pos >= 0:
                # 找到了content-length字段
                val_start = pattern_pos + len(cl_pattern)
                line_end = -1
                
                # 找到行尾
                for end_mark in [b'\r\n', b'\n']:
                    end_pos = modified_data.find(end_mark, val_start)
                    if end_pos > 0:
                        line_end = end_pos + len(end_mark)
                        break
                
                if line_end > val_start:
                    # 移除整行content-length
                    line_start = pattern_pos
                    # 如果前面有回车换行，也一起移除
                    if line_start >= 2 and modified_data[line_start-2:line_start] == b'\r\n':
                        line_start -= 2
                    elif line_start >= 1 and modified_data[line_start-1:line_start] == b'\n':
                        line_start -= 1
                    
                    modified_data = modified_data[:line_start] + modified_data[line_end:]
                    content_removed = True
                    logger.info(f"移除了content-length字段(二进制)")
                    # 由于数据已修改，重新从头开始查找
                    pattern_pos = modified_data.lower().find(cl_pattern.lower())
                else:
                    # 如果未找到完整行尾，尝试寻找其他终止符
                    for alt_end in [b';', b',', b' ', b'\t']:
                        end_pos = modified_data.find(alt_end, val_start)
                        if end_pos > 0:
                            line_end = end_pos + len(alt_end)
                            break
                    
                    if line_end > val_start:
                        # 移除字段值部分
                        modified_data = modified_data[:pattern_pos] + modified_data[line_end:]
                        content_removed = True
                        logger.info(f"移除了不完整的content-length字段(二进制)")
                        pattern_pos = modified_data.lower().find(cl_pattern.lower())
                    else:
                        # 继续查找下一个匹配位置
                        pattern_pos = modified_data.lower().find(cl_pattern.lower(), pattern_pos + 1)
        
        # 如果二进制方式未能移除，尝试HPACK方式
        if not content_removed:
            try:
                decoder = Decoder()
                encoder = Encoder()
                headers = decoder.decode(headers_data)
                new_headers = []
                cl_removed = False
                
                # 过滤掉所有content-length字段
                for name, value in headers:
                    name_str = name.decode() if isinstance(name, bytes) else name
                    is_content_length = isinstance(name_str, str) and name_str.lower() == "content-length"
                    if not is_content_length:
                        new_headers.append((name, value))
                    else:
                        cl_removed = True
                
                if cl_removed:
                    encoded_headers = encoder.encode(new_headers)
                    logger.info(f"移除了content-length字段(HPACK)")
                    return encoded_headers, True
            except Exception as e:
                logger.warning(f"HPACK移除content-length失败: {e}")
        
        return modified_data, content_removed or (modified_data != headers_data)
        
    except Exception as e:
        logger.error(f"移除content-length字段出错: {e}")
        logger.error(traceback.format_exc())
        return headers_data, False

def add_content_length_header(headers_data, content_length):
    """添加content-length字段到headers数据"""
    try:
        # 首先尝试HPACK方式添加
        try:
            decoder = Decoder()
            encoder = Encoder()
            headers = decoder.decode(headers_data)
            new_headers = []
            cl_added = False
            content_length_str = str(content_length)
            
            for name, value in headers:
                name_str = name.decode() if isinstance(name, bytes) else name
                is_content_length = isinstance(name_str, str) and name_str.lower() == "content-length"
                if is_content_length:
                    # 替换现有content-length
                    if isinstance(value, bytes):
                        new_headers.append((name, content_length_str.encode()))
                    else:
                        new_headers.append((name, content_length_str))
                    cl_added = True
                else:
                    new_headers.append((name, value))
            
            # 如果没有找到content-length，添加一个
            if not cl_added:
                content_length_key = "content-length"
                content_length_value = content_length_str
                
                # 使用与现有头字段一致的类型
                if any(isinstance(n, bytes) for n, _ in headers):
                    content_length_key = b"content-length"
                if any(isinstance(v, bytes) for _, v in headers):
                    content_length_value = content_length_str.encode()
                
                new_headers.append((content_length_key, content_length_value))
                cl_added = True
            
            if cl_added:
                new_data = encoder.encode(new_headers)
                logger.info(f"添加content-length: {content_length} (HPACK方式)")
                return new_data, True
        
        except Exception as e:
            logger.warning(f"HPACK添加content-length失败: {e}")
        
        # 如果HPACK方式失败，尝试二进制方式插入
        insert_positions = []
        
        # 查找最佳插入位置
        for marker in [b'\r\n\r\n', b'\n\n', b'\r\n', b'\n']:
            pos = headers_data.rfind(marker)
            if pos > 0:
                insert_positions.append((pos, 1))  # 权重1(高)
        
        # 在关键头部字段后插入
        for header_name in [b':status', b':path', b'location', b'date', b'server']:
            pos = headers_data.find(header_name)
            if pos > 0:
                line_end = -1
                for end_mark in [b'\r\n', b'\n']:
                    end_pos = headers_data.find(end_mark, pos)
                    if end_pos > 0:
                        line_end = end_pos + len(end_mark)
                        break
                if line_end > 0:
                    insert_positions.append((line_end, 2))  # 权重2(中)
        
        # 考虑末尾插入
        if len(headers_data) > 0:
            insert_positions.append((len(headers_data), 3))  # 权重3(低)
        
        # 尝试按优先级插入
        for pos, _ in sorted(insert_positions, key=lambda x: x[1]):
            try:
                if pos > 0 and headers_data[pos-1:pos] not in [b'\r', b'\n']:
                    cl_header = b'\r\ncontent-length: ' + str(content_length).encode()
                else:
                    cl_header = b'content-length: ' + str(content_length).encode()
                
                new_data = headers_data[:pos] + cl_header + headers_data[pos:]
                logger.info(f"添加content-length: {content_length} (二进制方式-位置:{pos})")
                return new_data, True
            except Exception as e:
                logger.warning(f"在位置 {pos} 添加content-length失败: {e}")
        
        # 最后手段：附加到数据末尾
        cl_header = b'\r\ncontent-length: ' + str(content_length).encode()
        new_data = headers_data + cl_header
        logger.info(f"添加content-length: {content_length} (附加到末尾)")
        return new_data, True
    
    except Exception as e:
        logger.error(f"添加content-length字段失败: {e}")
        logger.error(traceback.format_exc())
        return headers_data, False

def verify_content_length(data, expected_length):
    """验证数据中是否存在指定的content-length值"""
    try:
        for cl_pattern in [b'content-length:', b'Content-Length:']:
            pattern_pos = data.lower().find(cl_pattern.lower())
            while pattern_pos >= 0:
                val_start = pattern_pos + len(cl_pattern)
                val_end = -1
                
                # 寻找值的结束位置
                for end_mark in [b'\r\n', b'\n', b';', b',', b' ']:
                    end_pos = data.find(end_mark, val_start)
                    if end_pos > 0:
                        val_end = end_pos
                        break
                
                if val_end > val_start:
                    try:
                        cl_value = int(data[val_start:val_end].strip())
                        if cl_value == expected_length:
                            logger.info(f"验证成功: content-length = {cl_value}")
                            return True, cl_value
                        else:
                            logger.warning(f"content-length值不匹配: {cl_value} != {expected_length}")
                            return False, cl_value
                    except ValueError:
                        logger.warning(f"无法解析content-length值: {data[val_start:val_end].strip()}")
                
                # 继续查找下一个匹配位置
                pattern_pos = data.lower().find(cl_pattern.lower(), pattern_pos + 1)
        
        logger.warning("未找到content-length字段")
        return False, None
    except Exception as e:
        logger.error(f"验证content-length时出错: {e}")
        return False, None

def fix_pkt15_content_length(pcap_in, pcap_out=None):
    """
    专门修复第15个报文的content-length字段

    参数:
        pcap_in: 输入PCAP文件路径
        pcap_out: 输出PCAP文件路径 (如果为None，则生成默认输出路径)
    """
    # 生成默认输出路径
    if pcap_out is None:
        base_name = os.path.splitext(pcap_in)[0]
        pcap_out = f"{base_name}_fixed_pkt15.pcap"
    
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
    
    # 定义HTTP/2帧头解析函数
    def extract_http2_frame(data, offset):
        """解析HTTP/2帧，返回帧头、类型、数据和结束位置"""
        if offset + 9 > len(data):
            return None, None, None
        
        frame_len = int.from_bytes(data[offset:offset+3], byteorder='big')
        frame_type = data[offset+3]
        frame_flags = data[offset+4]
        stream_id = int.from_bytes(data[offset+5:offset+9], byteorder='big') & 0x7FFFFFFF
        
        # 检查帧长度是否超出数据范围
        if offset + 9 + frame_len > len(data):
            logger.warning(f"帧长度超出数据范围: {frame_len}，截断至数据末尾")
            frame_len = len(data) - (offset + 9)
        
        frame_data = data[offset+9:offset+9+frame_len]
        frame_end = offset + 9 + frame_len
        
        return {
            'length': frame_len,
            'type': frame_type,
            'flags': frame_flags,
            'stream_id': stream_id
        }, frame_data, frame_end
    
    # 提取所有帧
    frames = []
    offset = 0
    while offset < len(raw):
        frame_header, frame_data, frame_end = extract_http2_frame(raw, offset)
        if frame_header is None:
            break
        
        frames.append({
            'header': frame_header,
            'data': frame_data,
            'offset': offset,
            'end': frame_end,
        })
        offset = frame_end
    
    logger.info(f"第15个报文中找到 {len(frames)} 个帧")
    
    # 查找DATA帧和HEADERS帧
    data_frames = []
    headers_frames = []
    
    for frame in frames:
        if frame['header']['type'] == 0:  # DATA帧
            data_frames.append(frame)
        elif frame['header']['type'] == 1:  # HEADERS帧
            headers_frames.append(frame)
    
    if not data_frames:
        logger.error("未找到DATA帧")
        return False
    
    if not headers_frames:
        logger.error("未找到HEADERS帧")
        return False
    
    # 获取DATA帧长度（如果有多个DATA帧，取总和）
    data_len = sum(len(frame['data']) for frame in data_frames)
    logger.info(f"DATA帧总长度: {data_len}")
    
    # 清除所有HEADERS帧中现有的content-length字段，然后添加新的字段
    headers_modified = False
    
    # 尝试处理所有HEADERS帧，优先处理第一个
    for header_idx, headers_frame in enumerate(headers_frames):
        # 如果已经在前面的帧中成功修改了content-length，跳过后续帧
        if headers_modified and header_idx > 0:
            continue
            
        headers_data = headers_frame['data']
        
        # 步骤1: 移除所有现有的content-length字段
        cleaned_data, cleaned = remove_content_length_headers(headers_data)
        if cleaned:
            headers_data = cleaned_data
            headers_modified = True
            logger.info("成功移除现有content-length字段")
        
        # 步骤2: 添加新的content-length字段
        updated_data, updated = add_content_length_header(headers_data, data_len)
        if updated:
            headers_data = updated_data
            headers_modified = True
            logger.info(f"成功添加新的content-length: {data_len}")
        
        # 步骤3: 验证content-length字段是否正确设置
        is_valid, found_value = verify_content_length(headers_data, data_len)
        
        # 如果验证失败，但有其他HEADERS帧，继续尝试下一个
        if not is_valid and header_idx + 1 < len(headers_frames):
            logger.warning(f"第 {header_idx+1} 个HEADERS帧处理失败，尝试下一个")
            continue
        
        # 强制添加一个content-length字段，以防上面的步骤都失败了
        if not is_valid:
            logger.warning("未能正确设置content-length字段，尝试强制添加")
            best_pos = -1
            
            # 尝试找一个最佳插入点
            for marker in [b'\r\n\r\n', b'\n\n', b'\r\n', b'\n']:
                pos = headers_data.rfind(marker)
                if pos > 0:
                    best_pos = pos
                    break
            
            if best_pos > 0:
                cl_header = b'\r\ncontent-length: ' + str(data_len).encode()
                headers_data = headers_data[:best_pos] + cl_header + headers_data[best_pos:]
            else:
                cl_header = b'\r\ncontent-length: ' + str(data_len).encode()
                headers_data = headers_data + cl_header
                
            logger.info("强制添加content-length字段")
            headers_modified = True
            
            # 再次验证
            is_valid, found_value = verify_content_length(headers_data, data_len)
            if is_valid:
                logger.info("强制添加content-length后验证成功")
            else:
                logger.warning("强制添加content-length后验证仍失败")
        
        # 更新HEADERS帧
        headers_frame['header']['length'] = len(headers_data)
        headers_frame['data'] = headers_data
    
    # 如果HEADERS已修改，更新帧
    if headers_modified:
        # 重建报文负载
        new_payload = b''
        for frame in frames:
            # 构建帧头
            header_bytes = frame['header']['length'].to_bytes(3, byteorder='big')
            header_bytes += bytes([frame['header']['type']])
            header_bytes += bytes([frame['header']['flags']])
            header_bytes += (frame['header']['stream_id'] & 0x7FFFFFFF).to_bytes(4, byteorder='big')
            
            # 添加帧头和数据
            new_payload += header_bytes + frame['data']
        
        # 更新报文
        pkt15[Raw].load = new_payload
        logger.info(f"更新报文负载，新长度: {len(new_payload)}")
        
        # 重新计算校验和
        del pkt15[IP].len
        del pkt15[IP].chksum
        if pkt15.haslayer(TCP):
            del pkt15[TCP].chksum
        
        # 验证修改是否成功
        final_valid, final_value = verify_content_length(pkt15[Raw].load, data_len)
        if final_valid:
            logger.info(f"最终验证成功: content-length = {final_value}")
        else:
            logger.warning("最终验证失败，可能需要进一步检查")
        
        # 保存修改后的PCAP
        try:
            wrpcap(pcap_out, packets)
            logger.info(f"保存修改后的PCAP到 {pcap_out}")
            return True
        except Exception as e:
            logger.error(f"保存PCAP文件失败: {e}")
            logger.error(traceback.format_exc())
            return False
    
    logger.warning("未能修改content-length字段")
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='修复PCAP文件中第15个报文的content-length字段')
    parser.add_argument('-i', '--input', dest='input_file', required=True,
                        help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', default=None,
                        help='输出PCAP文件路径 (可选，默认为input_file加上_fixed_pkt15后缀)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='显示详细日志信息')

    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    success = fix_pkt15_content_length(args.input_file, args.output_file)
    if success:
        print("修复成功！")
    else:
        print("修复失败，请查看日志获取详细信息。")
