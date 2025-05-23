"""
逐行处理文件并修复特定行
"""

def fix_file():
    # 设置文件路径
    filepath = r"h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02_1515.py"
    
    # 读取文件内容
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    # 确认文件行数
    print(f"文件包含 {len(lines)} 行")
    
    # 定位到第2244行（Python索引是2243）
    target_line = 2244 - 1
    if target_line < len(lines):
        print(f"第2244行内容: {lines[target_line].rstrip()}")
        
        # 检查是否是预期的except行
        if "except Exception as e:" in lines[target_line]:
            # 修复问题 - 调整缩进
            fixed_line = lines[target_line].lstrip()  # 移除左侧所有空白
            proper_indent = ' ' * 16  # 16个空格的缩进
            lines[target_line] = proper_indent + fixed_line  # 添加正确的缩进
            
            # 同样修复下一行的缩进
            if target_line + 1 < len(lines):
                fixed_next_line = lines[target_line + 1].lstrip()
                lines[target_line + 1] = proper_indent + '    ' + fixed_next_line
            
            # 写回文件
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            print("文件已修复")
        else:
            print("第2244行不是预期的except行")
    else:
        print("文件行数不足")

if __name__ == "__main__":
    fix_file()
