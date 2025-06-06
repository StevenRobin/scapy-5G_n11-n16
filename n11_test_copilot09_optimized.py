# n11_test_copilot09_optimized.py - 优化版本
# 修复所有已知问题，提高字段修改的准确性和可靠性

import os
import re
import struct
from scapy.utils import rdpcap, wrpcap
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP
import binascii

# 环境设置
os.environ['SCAPY_USE_PCAPDNET'] = '0'
os.environ['SCAPY_USE_WINPCAPY'] = '0'

# 全局变量（与原代码保持一致）
sip1 = "50.0.0.1"
sport1 = 8080
dip1 = "60.0.0.1"
dport1 = 8080
auth2 = sip1
imsi1 = "460012300000001"
imei14 = "86111010000001"
gpsi1 = "8613900000001"
PduAddr1 = "100.0.0.1"
dnn1 = "dnn600000001"
tac1 = "100001"
cgi1 = "010000001"

UpfIP1 = "80.0.0.1"
UpTeid1 = 0x70000001
UpfIP2 = "70.0.0.1"  # gnbIP1的值
UpTeid2 = 0x30000001  # dnTEID1的值

CLIENT_IP_OLD = "121.1.1.10"
SERVER_IP_OLD = "123.1.1.10"
SV_DEFAULT = "00"
RE_IMSI = re.compile(r'imsi-\d+')

def luhn_checksum(numstr: str) -> int:
    """计算Luhn校验码"""
    digits = [int(x) for x in numstr]
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return (10 - (checksum % 10)) % 10

def inc_ip(ip_str: str) -> str:
    """IP地址递增（按16进制方式）"""
    parts = ip_str.split('.')
    ip_int = sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))
    ip_int += 1
    new_parts = [(ip_int >> (8 * (3 - i))) & 0xFF for i in range(4)]
    return '.'.join(map(str, new_parts))

def inc_hex(hex_val: int) -> int:
    """十六进制值递增"""
    return hex_val + 1

def inc_dec_str(dec_str: str) -> str:
    """十进制字符串递增"""
    return str(int(dec_str) + 1)

def extract_http2_frames(raw_data):
    """提取HTTP/2帧"""
    offset = 0
    frames = []
    while offset + 9 <= len(raw_data):
        length = int.from_bytes(raw_data[offset:offset+3], 'big')
        frame_type = raw_data[offset+3]
        flags = raw_data[offset+4]
        stream_id = int.from_bytes(raw_data[offset+5:offset+9], 'big') & 0x7FFFFFFF
        frame_data = raw_data[offset+9:offset+9+length]
        frames.append({
            'type': frame_type,
            'data': frame_data,
            'length': length,
            'flags': flags,
            'stream_id': stream_id
        })
        offset += 9 + length
    return frames

def hex_dump(data, title="数据"):
    """十六进制数据转储"""
    if not data:
        return f"{title}: (空)"
    hex_str = ' '.join(f'{b:02x}' for b in data[:64])  # 限制长度
    if len(data) > 64:
        hex_str += "..."
    return f"{title}: {hex_str}"

class BinaryFieldModifier:
    """二进制字段修改器 - 提供更可靠的字段修改功能"""
    
    def __init__(self):
        self.debug = True
        self.modifications = []
    
    def log(self, message):
        """调试日志"""
        if self.debug:
            print(f"[BFM] {message}")
    
    def find_and_replace_ip(self, data, old_ip_str, new_ip_str, context=""):
        """查找并替换IP地址"""
        old_ip_bytes = bytes([int(x) for x in old_ip_str.split('.')])
        new_ip_bytes = bytes([int(x) for x in new_ip_str.split('.')])
        
        pos = data.find(old_ip_bytes)
        if pos >= 0:
            modified_data = data[:pos] + new_ip_bytes + data[pos+4:]
            self.log(f"✅ {context} IP: {old_ip_str} -> {new_ip_str} at pos {pos}")
            self.modifications.append(f"{context} IP修改: {old_ip_str} -> {new_ip_str}")
            return modified_data, True
        else:
            self.log(f"❌ {context} 未找到IP {old_ip_str}")
            return data, False
    
    def find_and_replace_teid(self, data, old_teid, new_teid, search_after=0, context=""):
        """查找并替换TEID值"""
        old_teid_bytes = old_teid.to_bytes(4, 'big')
        new_teid_bytes = new_teid.to_bytes(4, 'big')
        
        pos = data.find(old_teid_bytes, search_after)
        if pos >= 0:
            modified_data = data[:pos] + new_teid_bytes + data[pos+4:]
            self.log(f"✅ {context} TEID: {hex(old_teid)} -> {hex(new_teid)} at pos {pos}")
            self.modifications.append(f"{context} TEID修改: {hex(old_teid)} -> {hex(new_teid)}")
            return modified_data, True
        else:
            self.log(f"❌ {context} 未找到TEID {hex(old_teid)}")
            return data, False
      def find_and_replace_dnn(self, data, new_dnn, context=""):
        """查找并替换DNN字段"""
        # 查找DNN标识 (element ID=0x25)
        dnn_pattern = b'\x25'
        pos = data.find(dnn_pattern)
        if pos >= 0:
            old_length = data[pos + 1] if pos + 1 < len(data) else 0
            old_dnn_end = pos + 2 + old_length
            
            # 构建新的DNN字段
            new_length = 13  # 固定长度
            new_dnn_bytes = new_dnn.encode('utf-8')
            new_dnn_field = bytes([new_length, len(new_dnn_bytes)]) + new_dnn_bytes
            
            modified_data = data[:pos+1] + new_dnn_field + data[old_dnn_end:]
            self.log(f"✅ {context} DNN: -> {new_dnn} (长度: {new_length})")
            self.modifications.append(f"{context} DNN修改: -> {new_dnn}")
            return modified_data, True
        else:
            self.log(f"❌ {context} 未找到DNN字段")
            return data, False
    
    def find_and_replace_pdu_address(self, data, new_ip_str, context=""):
        """查找并替换PDU address字段"""
        # 查找PDU address标识 (element ID=0x29)
        pdu_pattern = b'\x29\x05\x01'  # element ID=0x29, length=5, PDU session type=IPv4
        pos = data.find(pdu_pattern)
        if pos >= 0:
            ip_pos = pos + len(pdu_pattern)
            new_ip_bytes = bytes([int(x) for x in new_ip_str.split('.')])
            if ip_pos + 4 <= len(data):
                modified_data = data[:ip_pos] + new_ip_bytes + data[ip_pos+4:]
                self.log(f"✅ {context} PDU Address: -> {new_ip_str}")
                self.modifications.append(f"{context} PDU Address修改: -> {new_ip_str}")
                return modified_data, True
            else:
                self.log(f"❌ {context} PDU Address数据长度不足")
                return data, False
        else:
            self.log(f"❌ {context} 未找到PDU Address字段")
            return data, False

def modify_binary_elements_optimized(frame_data, pkt_idx):
    """优化版本的二进制字段修改函数"""
    global PduAddr1, dnn1, UpfIP1, UpTeid1, UpfIP2, UpTeid2
    
    modifier = BinaryFieldModifier()
    modifier.log(f"开始处理报文{pkt_idx+1}，数据长度: {len(frame_data)}")
    modifier.log(hex_dump(frame_data, f"报文{pkt_idx+1}原始数据"))
    
    modified_data = frame_data
    
    if pkt_idx == 46:  # 第47号报文
        modifier.log("=== 处理第47号报文 ===")
        
        # 1. 修改PDU address
        current_pdu = PduAddr1
        modified_data, success = modifier.find_and_replace_pdu_address(
            modified_data, current_pdu, "报文47")
        if success:
            PduAddr1 = inc_ip(PduAddr1)
        
        # 2. 修改DNN
        current_dnn = dnn1
        modified_data, success = modifier.find_and_replace_dnn(
            modified_data, current_dnn, "报文47")
        if success:
            numeric_part = int(''.join(filter(str.isdigit, dnn1)))
            prefix = dnn1.split(str(numeric_part))[0]
            dnn1 = f"{prefix}{numeric_part + 1}"
        
        # 3. 修改gTPTunnel字段 - UpfIP1和UpTeid1
        # 先尝试多种可能的IP地址查找
        current_upf_ip = UpfIP1
        current_upf_teid = UpTeid1
        
        # 尝试查找当前IP的前一个值（原始值）
        prev_upf_ip = inc_ip(current_upf_ip)  # 这里需要反向推导
        prev_upf_ip_parts = current_upf_ip.split('.')
        if int(prev_upf_ip_parts[3]) > 1:
            prev_upf_ip_parts[3] = str(int(prev_upf_ip_parts[3]) - 1)
            prev_upf_ip = '.'.join(prev_upf_ip_parts)
        else:
            prev_upf_ip = current_upf_ip  # 如果已经是第一个，就用当前值
        
        modified_data, success = modifier.find_and_replace_ip(
            modified_data, prev_upf_ip, current_upf_ip, "报文47 gTPTunnel")
        if success:
            UpfIP1 = inc_ip(UpfIP1)
            
            # 查找并修改TEID
            prev_teid = current_upf_teid - 1 if current_upf_teid > 1 else current_upf_teid
            modified_data, teid_success = modifier.find_and_replace_teid(
                modified_data, prev_teid, current_upf_teid, 0, "报文47 gTPTunnel")
            if teid_success:
                UpTeid1 = inc_hex(UpTeid1)
    
    elif pkt_idx == 48:  # 第49号报文
        modifier.log("=== 处理第49号报文 ===")
        
        # 修改gTPTunnel字段 - UpfIP2和UpTeid2
        current_gnb_ip = UpfIP2
        current_dn_teid = UpTeid2
        
        # 尝试查找当前IP的前一个值
        prev_gnb_ip_parts = current_gnb_ip.split('.')
        if int(prev_gnb_ip_parts[3]) > 1:
            prev_gnb_ip_parts[3] = str(int(prev_gnb_ip_parts[3]) - 1)
            prev_gnb_ip = '.'.join(prev_gnb_ip_parts)
        else:
            prev_gnb_ip = current_gnb_ip
        
        modified_data, success = modifier.find_and_replace_ip(
            modified_data, prev_gnb_ip, current_gnb_ip, "报文49 gTPTunnel")
        if success:
            UpfIP2 = inc_ip(UpfIP2)
            
            # 查找并修改TEID
            prev_teid = current_dn_teid - 1 if current_dn_teid > 1 else current_dn_teid
            modified_data, teid_success = modifier.find_and_replace_teid(
                modified_data, prev_teid, current_dn_teid, 0, "报文49 gTPTunnel")
            if teid_success:
                UpTeid2 = inc_hex(UpTeid2)
    
    modifier.log(hex_dump(modified_data, f"报文{pkt_idx+1}修改后数据"))
    modifier.log(f"本次修改摘要: {len(modifier.modifications)} 项修改")
    for mod in modifier.modifications:
        modifier.log(f"  - {mod}")
    
    return modified_data

def rebuild_mime_structure(frame_data, pkt_idx):
    """重建MIME结构（调用优化版本的修改函数）"""
    if not frame_data or len(frame_data) == 0:
        return frame_data
    
    boundary = b'--++Boundary'
    if boundary not in frame_data:
        return frame_data
    
    parts = frame_data.split(boundary)
    mime_parts = []
    
    for i, part in enumerate(parts):
        if i == 0:  # 第一个部分通常是空的前缀
            mime_parts.append(part)
            continue
          if b'\r\n\r\n' in part:
            headers_section, body_section = part.split(b'\r\n\r\n', 1)
            
            # 移除尾部的边界标记
            if b'\r\n--' in body_section:
                body_section = body_section.split(b'\r\n--', 1)[0]
            
            # 确保Content-Id存在
            if b'Content-Id:' not in headers_section:
                content_id = f"Part{i}"
                headers_section += f"\r\nContent-Id:{content_id}".encode()
            
            # 处理二进制部分的MIME结构（针对第47、49报文的第2个部分）
            if (pkt_idx == 46 or pkt_idx == 48) and i == 2:  # 第2个部分
                print(f"[处理] 修改报文{pkt_idx+1}第{i}个MIME部分的二进制内容")
                print(f"[DEBUG] 调用优化版modify_binary_elements之前，body_section长度: {len(body_section)}")
                body_section = modify_binary_elements_optimized(body_section, pkt_idx)
                print(f"[DEBUG] 调用优化版modify_binary_elements之后，body_section长度: {len(body_section)}")
            
            # 重建这个MIME部分
            rebuilt_part = headers_section + b'\r\n\r\n' + body_section
            mime_parts.append(rebuilt_part)
        else:
            # 处理没有分隔符的部分
            headers_section = part
            if b'\r\n--' in headers_section:
                headers_section = headers_section.split(b'\r\n--', 1)[0]
            
            if b'Content-Id:' not in headers_section and len(headers_section.strip()) > 0:
                content_id = f"Part{i}"
                headers_section += f"\r\nContent-Id:{content_id}".encode()
            
            mime_parts.append(headers_section)
    
    # 重建完整的MIME结构
    rebuilt_frame = boundary.join(mime_parts)
    return rebuilt_frame

# 其余函数保持不变...
def main_batch():
    """主要的批处理函数"""
    input_file = "pcap/N11_create_50p_portX.pcap"
    output_file = "pcap/N11_create_1001_optimized.pcap"
    
    print(f"读取文件: {input_file}")
    if not os.path.exists(input_file):
        print(f"输入文件不存在: {input_file}")
        return
    
    try:
        packets = rdpcap(input_file)
        print(f"成功读取 {len(packets)} 个数据包")
    except Exception as e:
        print(f"读取文件失败: {e}")
        return
    
    modified_packets = []
    
    for i, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            # 检查是否是第47或第49号报文
            if i in [46, 48]:  # 第47和第49号报文
                print(f"\n=== 处理第{i+1}号报文 ===")
                
                raw_data = bytes(pkt[Raw].load)
                frames = extract_http2_frames(raw_data)
                
                print(f"第{i+1}号报文包含 {len(frames)} 个HTTP/2帧")
                
                # 重建HTTP/2帧
                rebuilt_frames = []
                for frame in frames:
                    if frame['type'] == 0x0:  # DATA帧
                        print(f"处理DATA帧，原始长度: {frame['length']}")
                        modified_data = rebuild_mime_structure(frame['data'], i)
                        
                        # 重建帧头
                        new_length = len(modified_data)
                        frame_header = (
                            new_length.to_bytes(3, 'big') +
                            frame['type'].to_bytes(1, 'big') +
                            frame['flags'].to_bytes(1, 'big') +
                            frame['stream_id'].to_bytes(4, 'big')
                        )
                        rebuilt_frames.append(frame_header + modified_data)
                        print(f"重建DATA帧，新长度: {new_length}")
                    else:
                        # 其他帧类型保持不变
                        frame_header = (
                            frame['length'].to_bytes(3, 'big') +
                            frame['type'].to_bytes(1, 'big') +
                            frame['flags'].to_bytes(1, 'big') +
                            frame['stream_id'].to_bytes(4, 'big')
                        )
                        rebuilt_frames.append(frame_header + frame['data'])
                
                # 更新数据包的Raw层
                new_raw_data = b''.join(rebuilt_frames)
                pkt[Raw].load = new_raw_data
        
        modified_packets.append(pkt)
    
    # 写入输出文件
    try:
        wrpcap(output_file, modified_packets)        print(f"\n成功生成输出文件: {output_file}")
    except Exception as e:
        print(f"写入输出文件失败: {e}")

if __name__ == "__main__":
    print("=== 优化版程序启动 ===")
    print(f"初始变量值:")
    print(f"  PduAddr1: {PduAddr1}")
    print(f"  dnn1: {dnn1}")
    print(f"  UpfIP1: {UpfIP1}")
    print(f"  UpTeid1: {hex(UpTeid1)}")
    print(f"  UpfIP2: {UpfIP2}")
    print(f"  UpTeid2: {hex(UpTeid2)}")
    
    try:
        main_batch()
        print("\n=== 优化版程序正常结束 ===")
        print(f"最终变量值:")
        print(f"  PduAddr1: {PduAddr1}")
        print(f"  dnn1: {dnn1}")
        print(f"  UpfIP1: {UpfIP1}")
        print(f"  UpTeid1: {hex(UpTeid1)}")
        print(f"  UpfIP2: {UpfIP2}")
        print(f"  UpTeid2: {hex(UpTeid2)}")
    except Exception as e:
        print(f"=== 优化版程序异常结束: {e} ===")
        import traceback
        traceback.print_exc()
