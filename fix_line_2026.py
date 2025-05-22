#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
简单直接地修复n16_test_fixed02_1515.py文件中的语法错误
"""

import sys
import os

file_path = "n16_test_fixed02_1515.py"
if len(sys.argv) > 1:
    file_path = sys.argv[1]

print(f"开始修复文件: {file_path}")

try:
    # 读取文件内容
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    # 检查是否有足够的行数
    if len(lines) < 2026:
        print(f"文件只有 {len(lines)} 行，不包含第2026行")
        sys.exit(1)
        
    # 打印问题行
    print(f"原始第2026行: {lines[2025].strip()}")
    
    # 检查并修复语法错误
    if "if b'/pdu-sessions/'" in lines[2025] and "if b'http://'" in lines[2025]:
        # 分割行并插入换行和缩进
        parts = lines[2025].split("if b'http://'", 1)
        lines[2025] = parts[0] + "\n                    if b'http://'" + parts[1]
        print("已修复语法错误")
    elif 'if b"/pdu-sessions/"' in lines[2025] and 'if b"http://"' in lines[2025]:
        # 分割行并插入换行和缩进
        parts = lines[2025].split('if b"http://"', 1)
        lines[2025] = parts[0] + '\n                    if b"http://"' + parts[1]
        print("已修复语法错误")
    else:
        print("未发现预期的语法错误格式")
        print(f"第2025行: {lines[2024].strip()}")
        print(f"第2026行: {lines[2025].strip()}")
        print(f"第2027行: {lines[2026].strip()}")
        sys.exit(1)
        
    # 写回文件
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)
        
    print("修复完成，文件已保存")
    
except Exception as e:
    print(f"发生错误: {e}")
    sys.exit(1)
