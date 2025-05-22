#!/usr/bin/env python3
# 调用fix_pkt15_content_length.py中的apply_fix_to_file函数
from fix_pkt15_content_length import apply_fix_to_file
import traceback
import logging
import sys

# 确保日志输出到控制台
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',
                   handlers=[logging.StreamHandler(sys.stdout)])

# 应用修复到目标文件
target_file = "n16_test_fixed02.py"
print(f"开始对 {target_file} 应用修复...")

try:
    success = apply_fix_to_file(target_file)
    
    if success:
        print(f"修复应用成功! 可以查看修改后的 {target_file} 文件")
    else:
        print("修复应用失败，请查看上面的日志获取详细信息。")
except Exception as e:
    print(f"发生错误: {e}")
    print(traceback.format_exc())
