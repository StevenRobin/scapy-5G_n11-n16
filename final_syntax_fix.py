"""
使用最简单的方法修复语法错误，针对具体行进行修复
"""
import os
import sys
import re

# 配置固定的行号进行替换
LINE_1 = 2026  # 第一个有问题的行
LINE_2 = 2873  # 第二个有问题的行
FILE_PATH = "n16_test_fixed02_1515.py"  # 要修复的文件

def fix_specific_line(line_num, log_file):
    """修复特定行号的错误"""
    try:
        # 检查文件是否存在
        if not os.path.exists(FILE_PATH):
            log_file.write(f"错误：文件 {FILE_PATH} 不存在\n")
            return False
            
        # 读取文件内容
        with open(FILE_PATH, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            
        # 检查行号是否有效
        if line_num > len(lines):
            log_file.write(f"错误：文件只有 {len(lines)} 行，无法访问第 {line_num} 行\n")
            return False
            
        # 获取要修复的行
        idx = line_num - 1
        original_line = lines[idx]
        log_file.write(f"原始第 {line_num} 行: {original_line}")
        
        # 进行修复
        fixed_line = original_line.replace(
            "if b'/pdu-sessions/' in old_url:                    if b'http://'",
            "if b'/pdu-sessions/' in old_url:\n                    if b'http://'"
        )
        
        # 如果没有变化，尝试其他替换
        if fixed_line == original_line:
            fixed_line = original_line.replace(
                'if b"/pdu-sessions/" in old_url:                    if b"http://"',
                'if b"/pdu-sessions/" in old_url:\n                    if b"http://"'
            )
            
        # 检查是否修复成功
        if fixed_line != original_line:
            # 替换行
            lines[idx] = fixed_line
            log_file.write(f"修复后的行: {fixed_line}")
            
            # 写回文件
            with open(FILE_PATH, 'w', encoding='utf-8') as f:
                f.writelines(lines)
                
            log_file.write(f"已成功修复第 {line_num} 行\n")
            return True
        else:
            log_file.write(f"未能识别第 {line_num} 行中的错误模式\n")
            return False
            
    except Exception as e:
        log_file.write(f"修复第 {line_num} 行时出错: {str(e)}\n")
        return False

def main():
    # 创建日志文件
    log_path = "syntax_fix.log"
    with open(log_path, 'w', encoding='utf-8') as log_file:
        log_file.write(f"开始修复语法错误...\n")
        log_file.write(f"目标文件: {FILE_PATH}\n")
        
        # 修复第一个错误
        result1 = fix_specific_line(LINE_1, log_file)
        
        # 修复第二个错误
        result2 = fix_specific_line(LINE_2, log_file)
        
        # 输出总结
        if result1 or result2:
            log_file.write("修复完成。\n")
        else:
            log_file.write("没有修复任何行。\n")
            
    print(f"修复过程已完成，详细日志见: {log_path}")
    
if __name__ == "__main__":
    main()
