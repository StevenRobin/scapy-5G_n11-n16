#!/usr/bin/env python3
# 简单的PCAP修复工具 - 专门用于修复第15号报文中的server:SMF和content-length字段
import sys
import os
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP

# 简单的日志函数
def log(message):
    print(f"[LOG] {message}")

def error(message):
    print(f"[ERROR] {message}")

def fix_pcap(input_file, output_file):
    """修复PCAP文件中的第15号报文"""
    log(f"开始处理文件: {input_file}")
    
    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        error(f"输入文件 {input_file} 不存在")
        return False
    
    try:
        # 读取PCAP文件
        packets = rdpcap(input_file)
        log(f"成功读取PCAP文件，包含 {len(packets)} 个报文")
        
        # 检查是否有足够的报文
        if len(packets) < 15:
            error(f"PCAP文件中包含的报文数量不足，只有 {len(packets)} 个")
            return False
        
        # 获取第15号报文(索引14)
        pkt15 = packets[14]
        
        # 检查是否是TCP报文并且有负载
        if not pkt15.haslayer(TCP) or not pkt15.haslayer(Raw):
            error("第15号报文不是TCP报文或没有负载")
            return False
        
        # 获取原始负载
        payload = bytes(pkt15[Raw].load)
        log(f"第15号报文原始负载长度: {len(payload)}")
        
        # 查找字符串并进行简单替换
        # 1. 确保包含 server: SMF
        if b'server' not in payload.lower() and b'SMF' not in payload:
            log("未找到server:SMF，将进行添加")
            
            # 查找适合添加server字段的位置
            if b'\r\n\r\n' in payload:
                # 在双回车换行前添加
                pos = payload.find(b'\r\n\r\n')
                new_payload = payload[:pos] + b'\r\nserver: SMF' + payload[pos:]
                payload = new_payload
                log("添加了server:SMF字段")
            
            elif b'\r\n' in payload:
                # 在任意回车换行后添加
                pos = payload.find(b'\r\n') + 2
                new_payload = payload[:pos] + b'server: SMF\r\n' + payload[pos:]
                payload = new_payload
                log("添加了server:SMF字段")
        
        # 2. 确保包含 content-length 字段
        if b'content-length' not in payload.lower():
            log("未找到content-length字段，将进行添加")
            
            # 查找适合添加content-length字段的位置
            if b'\r\n\r\n' in payload:
                # 在双回车换行前添加
                pos = payload.find(b'\r\n\r\n')
                new_payload = payload[:pos] + b'\r\ncontent-length: 351' + payload[pos:]
                payload = new_payload
                log("添加了content-length字段")
            
            elif b'\r\n' in payload:
                # 在任意回车换行后添加
                pos = payload.find(b'\r\n') + 2
                new_payload = payload[:pos] + b'content-length: 351\r\n' + payload[pos:]
                payload = new_payload
                log("添加了content-length字段")
        
        # 更新报文负载
        pkt15[Raw].load = payload
        log(f"更新报文负载，新长度: {len(payload)}")
        
        # 重新计算校验和
        del pkt15[IP].len
        del pkt15[IP].chksum
        if pkt15.haslayer(TCP):
            del pkt15[TCP].chksum
        
        # 保存修改后的PCAP文件
        try:
            log(f"尝试保存修改后的PCAP文件: {output_file}")
            wrpcap(output_file, packets)
            log(f"成功保存修改后的PCAP文件: {output_file}")
            return True
        except Exception as e:
            error(f"保存PCAP文件时出错: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    except Exception as e:
        error(f"处理过程中出错: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函数"""
    # 解析命令行参数
    if len(sys.argv) != 3:
        print("用法: python script.py <输入PCAP> <输出PCAP>")
        return
      input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # 显示完整路径
    input_file = os.path.abspath(input_file)
    output_file = os.path.abspath(output_file)
    
    log(f"输入文件: {input_file}")
    log(f"输出文件: {output_file}")
    
    # 确保输出目录存在
    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        log(f"创建输出目录: {output_dir}")
    
    # 修复PCAP文件
    success = fix_pcap(input_file, output_file)
    
    if success:
        print("修复成功！")
    else:
        print("修复失败！")

if __name__ == "__main__":
    main()
