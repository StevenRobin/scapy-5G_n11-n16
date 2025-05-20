import scapy.all as scapy
import hpack
import time
import binascii
import sys
import re

def log_debug(message, level=1):
    """多级调试日志"""
    print(f"[DEBUG-{level}] {message}")

def log_info(message):
    """信息日志"""
    print(f"[INFO] {message}")

def log_error(message):
    """错误日志"""
    print(f"[ERROR] {message}")

def hex_dump(data, prefix=""):
    """十六进制打印数据"""
    if not data:
        return f"{prefix}[empty]"
    hex_str = binascii.hexlify(data).decode('ascii')
    return f"{prefix}{hex_str}"

def find_http2_frames_start(data, debug=True):
    """查找HTTP/2帧的真正起始位置"""
    # 扫描TCP流，寻找合法的HTTP/2帧序列
    for i in range(len(data) - 9):
        # 尝试解释为HTTP/2帧
        length = int.from_bytes(data[i:i+3], 'big')
        type_byte = data[i+3]
        flags = data[i+4] 
        stream_id = int.from_bytes(data[i+5:i+9], 'big') & 0x7fffffff

        # HTTP/2帧类型通常在0-9之间，帧长度不会超过16MB
        if 0 <= type_byte <= 9 and length < 16777216 and i + 9 + length <= len(data):
            # 再检查下一个连续帧
            next_pos = i + 9 + length
            if next_pos + 9 <= len(data):
                next_length = int.from_bytes(data[next_pos:next_pos+3], 'big')
                next_type = data[next_pos+3]
                if 0 <= next_type <= 9 and next_length < 16777216:
                    if debug:
                        log_debug(f"找到可能的HTTP/2帧起始点: 偏移={i}, 帧类型={type_byte}, 长度={length}", level=1)
                    return i

    log_error("未找到有效的HTTP/2帧序列")
    return 0

def parse_http2_frames(data, debug=True):
    """解析HTTP/2帧，带容错能力"""
    frames = []
    
    # 首先尝试找到HTTP/2帧的真正起始位置
    start_pos = find_http2_frames_start(data, debug)
    data = data[start_pos:]  # 调整数据起始点
    
    if debug:
        log_debug(f"解析HTTP/2帧，从偏移{start_pos}开始，剩余数据总长: {len(data)}字节", level=1)
        log_debug(f"数据前24字节: {hex_dump(data[:24])}", level=2)
    
    offset = 0
    frame_count = 0
    
    while offset + 9 <= len(data):
        try:
            length = int.from_bytes(data[offset:offset+3], 'big')
            type_byte = data[offset+3]
            flags = data[offset+4]
            stream_id = int.from_bytes(data[offset+5:offset+9], 'big') & 0x7fffffff
            
            # 检查帧长度是否合理
            if length > 16777215 or type_byte > 9:  # HTTP/2规范中帧类型为0-9
                log_error(f"偏移{offset}处有不合法的帧: 长度={length}, 类型={type_byte}")
                # 尝试查找下一个有效帧
                next_frame_pos = find_http2_frames_start(data[offset+1:], False)
                if next_frame_pos > 0:
                    offset += next_frame_pos + 1
                    continue
                else:
                    break
            
            # 帧类型名称，方便调试
            frame_types = {
                0x0: "DATA",
                0x1: "HEADERS",
                0x2: "PRIORITY",
                0x3: "RST_STREAM",
                0x4: "SETTINGS",
                0x5: "PUSH_PROMISE",
                0x6: "PING",
                0x7: "GOAWAY",
                0x8: "WINDOW_UPDATE",
                0x9: "CONTINUATION"
            }
            frame_type_name = frame_types.get(type_byte, f"UNKNOWN({type_byte})")
            
            # 获取帧数据
            if offset + 9 + length <= len(data):
                frame_data = data[offset+9:offset+9+length]
                if debug:
                    log_debug(f"偏移量 {offset}: {frame_type_name} 帧, 长度 {length}, 标志 0x{flags:02X}, 流ID {stream_id}", level=2)
                    if type_byte == 0x1 and length > 0:  # HEADERS
                        log_debug(f"  HEADERS帧数据: {hex_dump(frame_data[:min(20, length)])}{'...' if length > 20 else ''}", level=3)
                
                frames.append({
                    "type": type_byte,
                    "type_name": frame_type_name,
                    "flags": flags,
                    "stream_id": stream_id,
                    "data": frame_data,
                    "offset": offset + start_pos,  # 加上原始偏移
                    "length": length
                })
                frame_count += 1
                offset += 9 + length
            else:
                log_error(f"帧数据不完整: 需要{length}字节，但只有{len(data) - offset - 9}字节")
                break
                
        except Exception as e:
            log_error(f"解析帧时出错: {str(e)}")
            # 尝试继续解析
            offset += 1
    
    if debug:
        log_debug(f"成功解析{frame_count}个HTTP/2帧", level=1)
    return frames

def direct_binary_replace(data, target_url, new_host, debug=True):
    """直接在二进制数据中替换location URL的host部分"""
    # 3GPP N16接口HTTP/2响应常见格式: "location: http://server:port/nsmf-pdusession/..."
    old_data = data[:]
    
    # 构建正则表达式，用于查找和替换URL的host部分
    # 假设location格式为 "http://host:port/path"
    if isinstance(target_url, str):
        target_url = target_url.encode('utf-8')
    
    # 从URLs中提取服务器部分
    pattern = rb'(https?://)([^:/]+)(:[0-9]+)?(/.*)'
    
    def replace_host(match):
        scheme = match.group(1)
        old_host = match.group(2)
        port = match.group(3) or b''
        path = match.group(4)
        
        # 显示匹配信息
        if debug:
            log_debug(f"找到URL: {match.group(0).decode('utf-8', errors='replace')}", level=1)
            log_debug(f"  - 协议: {scheme.decode('utf-8')}", level=2)
            log_debug(f"  - 主机: {old_host.decode('utf-8')}", level=2)
            log_debug(f"  - 端口: {port.decode('utf-8') if port else '(无)'}", level=2)
            log_debug(f"  - 路径: {path.decode('utf-8')}", level=2)
        
        # 创建新URL
        new_host_bytes = new_host.encode('utf-8')
        if len(old_host) >= len(new_host_bytes):
            # 新主机名更短，填充空格
            padding = b' ' * (len(old_host) - len(new_host_bytes))
            return scheme + new_host_bytes + padding + port + path
        else:
            # 新主机名更长，可能需要截断
            log_error(f"新主机名'{new_host}'比原主机名'{old_host.decode('utf-8')}'长，可能导致截断")
            return scheme + new_host_bytes[:len(old_host)] + port + path
    
    # 特殊处理：包含主机名和路径的URL
    locations_found = 0
    modified_data = bytearray(data)
    
    # 手动字符串搜索和替换(二进制安全)
    search_start = 0
    while True:
        pos = data.find(b'location:', search_start)
        if pos == -1:
            pos = data.find(b'Location:', search_start)
        if pos == -1:
            break
            
        # 找到url开始的位置
        url_start = data.find(b'http', pos, pos+30)
        if url_start == -1:
            search_start = pos + 9
            continue
            
        # 找到URL结束位置
        url_end = url_start
        while url_end < len(data) and not (data[url_end] in [0, 10, 13]):
            url_end += 1
            
        url = data[url_start:url_end]
        if debug:
            log_debug(f"找到Location URL: {url.decode('utf-8', errors='replace')}", level=1)
            
        # 替换主机名
        try:
            new_url = re.sub(pattern, replace_host, url)
            if new_url != url:
                modified_data[url_start:url_end] = new_url
                locations_found += 1
                if debug:
                    log_debug(f"修改后URL: {new_url.decode('utf-8', errors='replace')}", level=1)
        except Exception as e:
            log_error(f"替换URL时出错: {str(e)}")
            
        search_start = url_end
    
    if locations_found > 0:
        log_info(f"直接替换了{locations_found}个location URL")
        return bytes(modified_data)
    else:
        log_error("未找到任何location URL")
        return data

def reassemble_tcp_stream(packets, debug=True):
    """将同一TCP流的所有Raw负载拼成一个字节流，并记录每个包的起止偏移"""
    stream = b''
    pkt_index = []
    
    log_info("开始TCP流重组...")
    for idx, pkt in enumerate(packets):
        if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
            raw = bytes(pkt["Raw"].load)
            pkt_index.append((len(stream), len(stream)+len(raw), idx))  # 起止偏移, 包序号
            if debug:
                log_debug(f"包 #{idx+1}: TCP SEQ={pkt['TCP'].seq}, 负载大小={len(raw)}, 流偏移={len(stream)}", level=1)
            stream += raw
    
    log_info(f"TCP流重组完成，共计{len(stream)}字节")
    return stream, pkt_index

def split_stream_to_packets(modified_stream, pkt_index, packets, debug=True):
    """将修改后的流分割回原始TCP包"""
    mod_packets = packets[:]
    
    log_info("开始将修改后的流拆分回TCP包...")
    for start, end, idx in pkt_index:
        if mod_packets[idx].haslayer("Raw"):
            # 提取这个包对应的片段
            if start < len(modified_stream) and end <= len(modified_stream):
                new_payload = modified_stream[start:end]
                old_payload = bytes(packets[idx]["Raw"].load)
                
                if debug and new_payload != old_payload:
                    log_debug(f"包 #{idx+1}: 负载已修改, 原长度={len(old_payload)}, 新长度={len(new_payload)}")
                    
                mod_packets[idx]["Raw"].load = new_payload
                # 清除校验和，让scapy重新计算
                if mod_packets[idx].haslayer("TCP"):
                    del mod_packets[idx]["TCP"].chksum
                if mod_packets[idx].haslayer("IP"):
                    del mod_packets[idx]["IP"].chksum
            else:
                log_error(f"流切片错误: 包#{idx+1}对应偏移[{start}:{end}]超出修改后流长度{len(modified_stream)}")
    
    log_info("TCP包拆分完成")
    return mod_packets

def modify_location_direct(
    pcap_path,
    new_host,
    out_pcap,
    target_location="http://",
    debug=True
):
    start_time = time.time()
    log_info(f"开始处理PCAP文件: {pcap_path}")
    
    # 1. 读取PCAP文件
    log_info("读取PCAP文件...")
    packets = scapy.rdpcap(pcap_path)
    log_info(f"读取完成，共{len(packets)}个包")
    
    # 2. 拼接TCP负载为完整HTTP/2字节流
    tcp_payload_stream, pkt_index = reassemble_tcp_stream(packets, debug)
    
    # 3. 直接在二进制层面替换location URL
    log_info("直接在二进制数据中替换location URL...")
    modified_stream = direct_binary_replace(tcp_payload_stream, target_location, new_host, debug)
    
    # 4. 拆包：将新流拆回原TCP包写回pcap
    log_info("将修改后的流拆分回TCP包...")
    mod_packets = split_stream_to_packets(modified_stream, pkt_index, packets, debug)
    
    # 5. 写入新的PCAP文件
    scapy.wrpcap(out_pcap, mod_packets)
    end_time = time.time()
    log_info(f"修改完成，PCAP已保存为: {out_pcap}")
    log_info(f"总处理时间: {end_time - start_time:.2f}秒")

if __name__ == "__main__":
    pcap_file = "pcap/N16_create_16p.pcap"
    new_host = "10.10.10.10:8000"
    out_pcap = "pcap/n16_modLocation_04.pcap"
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    if len(sys.argv) > 2:
        new_host = sys.argv[2]
    if len(sys.argv) > 3:
        out_pcap = sys.argv[3]
    
    debug_mode = True  # 设置为False可减少调试信息
    
    log_info(f"输入文件: {pcap_file}")
    log_info(f"新host: {new_host}")
    log_info(f"输出文件: {out_pcap}")
    
    # 直接二进制替换方法 - 更简单有效
    modify_location_direct(
        pcap_path=pcap_file,
        new_host=new_host,
        out_pcap=out_pcap,
        target_location="http://",  # 默认以http://开头的URL
        debug=debug_mode
    )