#!/usr/bin/env python3
"""
检查并修复n16_test_fixed02.py中的语法错误
"""
import re
import sys

def fix_syntax_errors(file_path):
    """处理并修复文件中的语法错误"""
    print(f"开始处理文件: {file_path}")
    
    # 读取文件
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # 检查第665-675行
    problem_line_range = range(665, 675)
    
    # 创建修复后的内容
    fixed_lines = []
    skip_next = False
    
    for i, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue
            
        line_num = i + 1  # 行号从1开始
        
        # 特定修复 - 处理第669行附近的问题
        if line_num == 669:
            # 拆分多条语句为多行
            if "尝试恢复措施" in line and "try:" in line:
                parts = line.split("尝试恢复措施")
                if len(parts) > 1:
                    fixed_lines.append(parts[0] + "尝试恢复措施\n")
                    indent = re.match(r'^(\s*)', line).group(1)
                    fixed_lines.append(f"{indent}    try:\n")
                    continue
        
        fixed_lines.append(line)
    
    # 写回修复后的内容
    backup_path = file_path + ".bak"
    print(f"创建备份文件: {backup_path}")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"写入修复后的文件: {file_path}")
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)
    
    print("完成！")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        file_path = "h:\\pythonProject\\study_01\\scapy-5G_n11-n16\\n16_test_fixed02.py"
    else:
        file_path = sys.argv[1]
    
    success = fix_syntax_errors(file_path)
    if success:
        print("文件已修复，请尝试再次运行。")
    else:
        print("修复失败，请手动检查文件。")
