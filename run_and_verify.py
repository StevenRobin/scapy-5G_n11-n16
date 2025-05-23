#!/usr/bin/env python3
# 运行n16_test_fixed02.py并验证修复效果
import os
import subprocess
import sys

def run_process_and_verify():
    """运行处理并验证结果"""
    # 确保输出目录存在
    os.makedirs("pcap", exist_ok=True)
    
    # 文件路径
    input_pcap = "pcap/N16_create_16p.pcap"
    output_pcap = "pcap/N16_fixed_pkt15.pcap"
    
    # 检查输入文件是否存在
    if not os.path.exists(input_pcap):
        print(f"错误: 输入文件 {input_pcap} 不存在")
        return False
    
    # 运行n16_test_fixed02.py处理PCAP文件
    try:
        print(f"开始处理PCAP文件...")
        subprocess.run(
            [sys.executable, "n16_test_fixed02.py", "-i", input_pcap, "-o", output_pcap],
            check=True
        )
        print(f"PCAP处理完成!")
    except subprocess.CalledProcessError as e:
        print(f"处理PCAP文件失败: {e}")
        return False
    
    # 验证处理结果
    try:
        print(f"验证处理结果...")
        subprocess.run(
            [sys.executable, "verify_pkt15.py", output_pcap],
            check=True
        )
        print(f"验证完成!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"验证失败: {e}")
        return False

if __name__ == "__main__":
    success = run_process_and_verify()
    if success:
        print("整个处理和验证过程成功完成!")
    else:
        print("处理或验证过程中出现错误，请查看上面的输出获取详细信息。")
