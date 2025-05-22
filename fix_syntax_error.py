#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
修复n16_test_fixed02_1515.py文件中的语法错误
错误位于2026行的嵌套if语句
"""

import re
import os

print(f"当前工作目录: {os.getcwd()}")
file_path = 'n16_test_fixed02_1515.py'

if not os.path.exists(file_path):
    print(f"错误：文件 '{file_path}' 不存在！")
    exit(1)

print(f"文件大小: {os.path.getsize(file_path)} 字节")

# 直接读取2025-2027行
try:
    with open(file_path, 'rb') as f:
        lines = f.readlines()
        if len(lines) >= 2027:
            print(f"第2025-2027行内容:")
            for i in range(2025, min(2028, len(lines))):
                print(f"行 {i+1}: {lines[i].rstrip().decode('utf-8', errors='replace')}")
        else:
            print(f"文件只有 {len(lines)} 行，无法读取第2026行")
except Exception as e:
    print(f"读取特定行时发生错误: {e}")

# 打开文件以二进制读取模式
try:
    with open(file_path, 'rb') as f:
        content = f.read()
    print(f"成功读取文件内容，大小: {len(content)} 字节")
except Exception as e:
    print(f"读取文件时发生错误: {e}")
    exit(1)

# 实验1: 使用正则表达式匹配
print("\n尝试使用正则表达式匹配错误模式...")
patterns = [
    rb'if\s+b[\'"]\/pdu-sessions\/[\'"]\s+in\s+old_url:\s+if\s+b[\'"]http:\/\/[\'"]\s+in\s+old_url:',
    rb'if\s+b.\/pdu-sessions\/.\s+in\s+old_url:\s+if\s+b.http:\/\/.\s+in\s+old_url:',
    rb'if b.\/pdu-sessions\/. in old_url:\s+if b.http:\/\/. in old_url:',
]

for i, pattern in enumerate(patterns):
    matches = re.findall(pattern, content)
    if matches:
        print(f'模式 {i+1}: 找到 {len(matches)} 个匹配项')
        for j, match in enumerate(matches):
            print(f"  匹配项 {j+1}: {match[:50]}...")
            # 在第一个冒号后添加换行和缩进
            fixed = re.sub(rb':\s+if', b':\n                    if', match)
            content = content.replace(match, fixed)
            print("  已修复")
        
        # 写回文件
        with open(file_path, 'wb') as f:
            f.write(content)
        print('替换完成，成功修复语法错误！')
        exit(0)
    else:
        print(f'模式 {i+1}: 未找到匹配项')

# 实验2: 尝试硬编码的字符串替换
print("\n尝试使用硬编码字符串替换...")
error_patterns = [
    (b'if b\'/pdu-sessions/\' in old_url:                    if b\'http://\' in old_url:', 
     b'if b\'/pdu-sessions/\' in old_url:\n                    if b\'http://\' in old_url:'),
    (b'if b"/pdu-sessions/" in old_url:                    if b"http://" in old_url:', 
     b'if b"/pdu-sessions/" in old_url:\n                    if b"http://" in old_url:'),
    (b'if b\'/pdu-sessions/\' in old_url:                   if b\'http://\' in old_url:', 
     b'if b\'/pdu-sessions/\' in old_url:\n                    if b\'http://\' in old_url:'),
    (b'if b"/pdu-sessions/" in old_url:                   if b"http://" in old_url:', 
     b'if b"/pdu-sessions/" in old_url:\n                    if b"http://" in old_url:'),
]

for i, (error, fixed) in enumerate(error_patterns):
    if error in content:
        print(f"找到硬编码模式 {i+1}")
        content = content.replace(error, fixed)
        with open(file_path, 'wb') as f:
            f.write(content)
        print('替换完成，成功修复语法错误！')
        exit(0)
    else:
        print(f"硬编码模式 {i+1} 未找到")

# 实验3: 直接使用行号定位和替换
print("\n尝试使用行号直接定位和替换...")
try:
    with open(file_path, 'rb') as f:
        lines = f.readlines()
    
    if len(lines) >= 2026:
        line_2026 = lines[2025].rstrip()  # Python索引从0开始，所以2026行是索引2025
        print(f"第2026行内容: {line_2026.decode('utf-8', errors='replace')}")
        
        if b'if b' in line_2026 and b'pdu-sessions' in line_2026 and b'http://' in line_2026:
            # 在这种情况下，我们知道这一行包含了两个if语句
            parts = line_2026.split(b'if b', 1)
            if len(parts) > 1:
                # 第一部分是"if b'/pdu-sessions/' in old_url:"这样的内容
                # 第二部分以"http://"开头，我们需要分割它
                lines[2025] = parts[0] + b'if b' + parts[1].split(b'if b', 1)[0] + b'\n                    if b' + parts[1].split(b'if b', 1)[1]
                
                with open(file_path, 'wb') as f:
                    f.writelines(lines)
                print("使用行号方法成功修复语法错误！")
                exit(0)
    else:
        print(f"文件只有 {len(lines)} 行，无法定位第2026行")
except Exception as e:
    print(f"使用行号方法时发生错误: {e}")

print("\n所有修复尝试均失败，请手动检查文件。")
