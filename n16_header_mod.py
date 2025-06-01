from scapy.all import rdpcap, TCP, Raw, IP, wrpcap
import sys
import os
import shutil
import re
from datetime import datetime
from hpack import Decoder, Encoder

def modify_headers_from_pcap(input_pcap, output_pcap, target_indices=[9, 13], auth2="60.0.0.1", pduSessionId2="10000001"):
    """
    修改PCAP文件中指定报文的HTTP/2头部字段（HPACK解码/编码方式）
    
    Args:
        input_pcap: 输入PCAP文件路径
        output_pcap: 输出PCAP文件路径
        target_indices: 目标报文编号列表
        auth2: 新的authority值（不包含端口）
        pduSessionId2: 新的PDU Session ID
    
    Returns:
        bool: 修改是否成功
    """
    # 检查输入文件是否存在
    if not os.path.exists(input_pcap):
        print(f"错误: 输入文件 {input_pcap} 不存在")
        return False
    
    try:
        packets = rdpcap(input_pcap)
        print(f"✓ 成功读取 {len(packets)} 个数据包")
    except Exception as e:
        print(f"✗ 读取PCAP文件失败: {e}")
        return False
    
    modified_packets = 0
    modification_log = []
    # 为每个流维护HPACK解码器
    flow_decoders = {}
    for idx, pkt in enumerate(packets, 1):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        if pkt.haslayer(IP):
            flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        else:
            flow = None
        if flow and flow not in flow_decoders:
            flow_decoders[flow] = Decoder()
        decoder = flow_decoders.get(flow, Decoder())
        raw_data = bytes(pkt[Raw].load)
        # HTTP/2帧解析
        offset = 0
        if len(raw_data) >= 24 and raw_data.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'):
            offset = 24
        frames = []
        while offset + 9 <= len(raw_data):
            length = int.from_bytes(raw_data[offset:offset+3], 'big')
            type_ = raw_data[offset+3]
            flags = raw_data[offset+4]
            stream_id = int.from_bytes(raw_data[offset+5:offset+9], 'big') & 0x7FFFFFFF
            if offset + 9 + length > len(raw_data):
                break
            payload = raw_data[offset+9:offset+9+length]
            frames.append((type_, flags, stream_id, payload, offset))
            offset += 9 + length
        # 只处理目标报文
        if idx in target_indices:
            new_frames = []
            packet_modified = False
            packet_log = []
            for type_, flags, stream_id, payload, frame_offset in frames:
                if type_ == 0x01:  # HEADERS帧
                    try:
                        headers = decoder.decode(payload)
                        new_headers = []
                        for name, value in headers:
                            name_str = name.decode('utf-8') if isinstance(name, bytes) else str(name)
                            value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
                            if name_str == ':authority' and '200.20.20.26:8080' in value_str:
                                new_value = f'{auth2}:8080'
                                new_headers.append((name, new_value.encode('utf-8')))
                                packet_log.append(f'Authority: {value_str} -> {new_value}')
                                packet_modified = True
                            elif name_str == ':path' and '461977034' in value_str:
                                new_value = value_str.replace('461977034', pduSessionId2)
                                new_headers.append((name, new_value.encode('utf-8')))
                                packet_log.append(f'PDU Session ID: {value_str} -> {new_value}')
                                packet_modified = True
                            else:
                                new_headers.append((name, value))
                        if packet_modified:
                            encoder = Encoder()
                            new_payload = encoder.encode(new_headers)
                            new_frames.append((type_, flags, stream_id, new_payload, frame_offset))
                        else:
                            new_frames.append((type_, flags, stream_id, payload, frame_offset))
                    except Exception as e:
                        new_frames.append((type_, flags, stream_id, payload, frame_offset))
                else:
                    new_frames.append((type_, flags, stream_id, payload, frame_offset))
            # 重建HTTP/2数据包
            if packet_modified:
                new_raw = bytearray()
                for t, f, sid, pl, off in new_frames:
                    l = len(pl)
                    new_raw.extend(l.to_bytes(3, 'big'))
                    new_raw.append(t)
                    new_raw.append(f)
                    new_raw.extend(sid.to_bytes(4, 'big'))
                    new_raw.extend(pl)
                pkt[Raw].load = bytes(new_raw)
                modified_packets += 1
                modification_log.append({'packet_index': idx, 'modifications': packet_log})
        else:
            # 非目标包只维护解码器状态
            for type_, _, _, payload, _ in frames:
                if type_ == 0x01:
                    try:
                        decoder.decode(payload)
                    except:
                        pass
    # 保存修改后的数据包
    try:
        output_dir = os.path.dirname(output_pcap)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        wrpcap(output_pcap, packets)
        print(f"\n✓ 共修改了 {modified_packets} 个数据包，保存到 {output_pcap}")
        log_content = generate_modification_log(input_pcap, output_pcap, modification_log, auth2, pduSessionId2)
        log_file = output_pcap.replace('.pcap', '_modification_log.txt')
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(log_content)
        print(f"✓ 修改日志已保存到 {log_file}")
        return True
    except Exception as e:
        print(f"✗ 保存PCAP文件失败: {e}")
        return False

def generate_modification_log(input_pcap, output_pcap, modification_log, auth2, pduSessionId2):
    """生成详细的修改日志"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_content = f"""PCAP文件修改日志
==========================================
修改时间: {timestamp}
输入文件: {input_pcap}
输出文件: {output_pcap}
参数设置:
  - Authority (auth2): {auth2}
  - PDU Session ID (pduSessionId2): {pduSessionId2}

修改详情:
"""
    
    if modification_log:
        for entry in modification_log:
            log_content += f"\n报文 {entry['packet_index']}:\n"
            for mod in entry['modifications']:
                log_content += f"  - {mod}\n"
    else:
        log_content += "\n未发现需要修改的内容\n"
    
    log_content += f"\n总计修改报文数: {len(modification_log)}\n"
    return log_content

def backup_file(file_path):
    """备份原始文件"""
    if os.path.exists(file_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{file_path}.backup_{timestamp}"
        try:
            shutil.copy2(file_path, backup_path)
            print(f"✓ 原文件已备份到 {backup_path}")
            return backup_path
        except Exception as e:
            print(f"✗ 备份文件失败: {e}")
    return None

def validate_parameters(auth2, pduSessionId2):
    """验证输入参数的有效性"""
    is_valid = True
    
    # 验证IP地址格式
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, auth2):
        print(f"⚠ 警告: authority地址格式可能不正确: {auth2}")
        # 验证IP地址范围
        try:
            parts = auth2.split('.')
            for part in parts:
                if not (0 <= int(part) <= 255):
                    print(f"⚠ 警告: IP地址段超出范围(0-255): {part}")
        except:
            pass
    
    # 验证PDU Session ID是否为数字
    if not pduSessionId2.isdigit():
        print(f"⚠ 警告: PDU Session ID应为数字: {pduSessionId2}")
        is_valid = False
    
    # 检查长度限制
    original_auth_len = len('200.20.20.26:8080')
    new_auth_len = len(f'{auth2}:8080')
    if new_auth_len > original_auth_len:
        print(f"✗ 错误: 新的authority地址太长({new_auth_len} > {original_auth_len})，会破坏报文结构")
        is_valid = False
    
    # 检查PDU Session ID长度
    if len(pduSessionId2) > 15:  # 合理的长度限制
        print(f"⚠ 警告: PDU Session ID过长: {pduSessionId2}")
    
    return is_valid

def print_usage():
    """打印使用说明"""
    print("""
使用方法:
    python n16_header_mod.py [authority_ip] [pdu_session_id]

参数说明:
    authority_ip    : 新的authority IP地址 (默认: 60.0.0.1)
    pdu_session_id  : 新的PDU Session ID (默认: 10000001)

示例:
    python n16_header_mod.py                     # 使用默认参数
    python n16_header_mod.py 192.168.1.100      # 只指定IP
    python n16_header_mod.py 192.168.1.100 20000002  # 指定IP和ID

注意事项:
    - authority IP地址长度不能超过原始地址长度
    - PDU Session ID必须为纯数字
    - 原始文件会自动备份
    """)

def main():
    """主函数"""
    # 显示程序信息
    print("=" * 60)
    print("HTTP/2 Headers修改工具 v2.0")
    print("=" * 60)
    
    # 处理命令行参数
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', '/?']:
        print_usage()
        return
    
    # 设置默认参数
    input_pcap = "pcap/N16_release_18p.pcap"
    output_pcap = "pcap/N16_release_1001.pcap"
    auth2 = "60.0.0.1"
    pduSessionId2 = "10000001"
    
    # 解析命令行参数
    if len(sys.argv) > 1:
        auth2 = sys.argv[1]
    if len(sys.argv) > 2:
        pduSessionId2 = sys.argv[2]
    
    print(f"配置参数:")
    print(f"  输入文件: {input_pcap}")
    print(f"  输出文件: {output_pcap}")
    print(f"  Authority IP: {auth2}")
    print(f"  PDU Session ID: {pduSessionId2}")
    print(f"  目标报文: [9, 13]")
    print("-" * 60)
    
    # 验证参数
    if not validate_parameters(auth2, pduSessionId2):
        print("\n✗ 参数验证失败，程序退出")
        sys.exit(1)
    
    # 备份原文件（如果输出文件已存在）
    backup_path = backup_file(output_pcap)
    
    # 执行修改
    print(f"\n开始处理...")
    success = modify_headers_from_pcap(input_pcap, output_pcap, [9, 13], auth2, pduSessionId2)
    
    if success:
        print(f"\n{'='*60}")
        print("✓ 修改完成！")
        if backup_path:
            print(f"✓ 原文件已备份: {backup_path}")
        print(f"✓ 新文件已生成: {output_pcap}")
        print(f"{'='*60}")
    else:
        print(f"\n{'='*60}")
        print("✗ 修改失败！")
        print(f"{'='*60}")
        sys.exit(1)

if __name__ == "__main__":
    main()
