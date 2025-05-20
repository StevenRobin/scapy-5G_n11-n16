#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
批量处理多个PCAP文件，修复第15个报文的content-length字段
"""
from fix_pkt15_content_length import fix_pkt15_content_length
import argparse
import os
import glob
import logging
import time

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"fix_pkt15_batch_{time.strftime('%Y%m%d_%H%M%S')}.log", mode="w"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def process_pcap_files(input_pattern, output_dir=None):
    """
    处理匹配指定模式的所有PCAP文件

    参数:
        input_pattern: 输入文件的glob模式，如 "pcap/*.pcap"
        output_dir: 输出目录，如果不指定则与输入文件相同目录
    """
    # 查找匹配的文件
    pcap_files = glob.glob(input_pattern)
    if not pcap_files:
        logger.error(f"没有找到匹配的PCAP文件: {input_pattern}")
        return False
    
    logger.info(f"找到 {len(pcap_files)} 个匹配的PCAP文件")
    success_count = 0
    failure_count = 0

    for pcap_file in pcap_files:
        # 确定输出文件路径
        if output_dir:
            base_name = os.path.basename(pcap_file)
            output_file = os.path.join(output_dir, f"{os.path.splitext(base_name)[0]}_fixed_pkt15.pcap")
        else:
            output_file = None  # 使用默认命名方式
        
        logger.info(f"处理文件: {pcap_file}")
        try:
            result = fix_pkt15_content_length(pcap_file, output_file)
            if result:
                logger.info(f"成功修复文件: {pcap_file}")
                success_count += 1
            else:
                logger.warning(f"修复失败: {pcap_file}")
                failure_count += 1
        except Exception as e:
            logger.error(f"处理文件时出错: {pcap_file}: {e}")
            failure_count += 1
    
    logger.info(f"批处理完成: 成功 {success_count} 个, 失败 {failure_count} 个")
    return success_count > 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='批量修复PCAP文件中第15个报文的content-length字段')
    parser.add_argument('-i', '--input', dest='input_pattern', required=True,
                        help='输入文件匹配模式，例如 "pcap/*.pcap"')
    parser.add_argument('-o', '--output-dir', dest='output_dir', default=None,
                        help='输出目录 (可选，默认与输入文件相同目录)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='显示详细日志信息')

    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    if args.output_dir and not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        logger.info(f"创建输出目录: {args.output_dir}")
    
    success = process_pcap_files(args.input_pattern, args.output_dir)
    
    if success:
        print("批处理完成，至少有一个文件成功修复！")
    else:
        print("批处理完成，但没有文件被成功修复。")
