#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
组合运行n16_test_fixed02.py和fix_pkt15_content_length.py，完整处理PCAP文件
"""
import subprocess
import os
import argparse
import logging
import time

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"n16_combined_process_{time.strftime('%Y%m%d_%H%M%S')}.log", mode="w"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def process_pcap_file(input_file, output_file, intermediate_file=None):
    """
    组合处理PCAP文件，通过n16_test_fixed02.py和fix_pkt15_content_length.py
    
    参数:
        input_file: 输入PCAP文件路径
        output_file: 最终输出PCAP文件路径
        intermediate_file: 中间临时文件路径 (如果不指定，将自动生成)
    """
    if not intermediate_file:
        basename = os.path.splitext(output_file)[0]
        intermediate_file = f"{basename}_intermediate.pcap"
    
    try:        # 第1步: 运行n16_test_fixed02.py处理基本内容
        logger.info(f"步骤1: 使用n16_test_fixed02.py处理文件 {input_file}")
        cmd1 = ["python", "n16_test_fixed02.py", "-i", input_file, "-o", intermediate_file]
        print(f"执行命令: {' '.join(cmd1)}")
        process1 = subprocess.run(cmd1)
        
        if process1.returncode != 0:
            logger.error(f"n16_test_fixed02.py处理失败，返回代码: {process1.returncode}")
            return False
        
        # 确认中间文件是否存在
        if not os.path.exists(intermediate_file):
            logger.error(f"中间文件不存在: {intermediate_file}")
            return False
            
        logger.info("n16_test_fixed02.py处理成功")
        
        # 第2步: 运行fix_pkt15_content_length.py修复第15个包的content-length
        logger.info(f"步骤2: 使用fix_pkt15_content_length.py修复第15包content-length")
        cmd2 = ["python", "fix_pkt15_content_length.py", "-i", intermediate_file, "-o", output_file]
        print(f"执行命令: {' '.join(cmd2)}")
        process2 = subprocess.run(cmd2)
        
        if process2.returncode != 0:
            logger.error(f"fix_pkt15_content_length.py处理失败，返回代码: {process2.returncode}")
            return False
            
        # 确认最终文件是否存在
        if not os.path.exists(output_file):
            logger.error(f"输出文件不存在: {output_file}")
            return False
        
        logger.info("fix_pkt15_content_length.py处理成功")
        logger.info(f"完整处理完成，输出文件: {output_file}")
        return True
    
    except Exception as e:
        logger.error(f"处理过程中出错: {e}")
        return False
    finally:
        # 清理中间文件（可选）
        if os.path.exists(intermediate_file) and intermediate_file != output_file:
            try:
                # os.remove(intermediate_file)  # 如果需要保留中间文件，可以注释此行
                pass
            except:
                pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='组合处理N16 PCAP文件')
    parser.add_argument('-i', '--input', dest='input_file', required=True,
                        help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', required=True,
                        help='输出PCAP文件路径')
    parser.add_argument('-t', '--temp', dest='temp_file', default=None,
                        help='中间临时文件路径 (可选)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='显示详细日志信息')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    success = process_pcap_file(args.input_file, args.output_file, args.temp_file)
    
    if success:
        print(f"处理成功，输出文件保存在: {args.output_file}")
    else:
        print("处理失败，请查看日志获取详细信息")
