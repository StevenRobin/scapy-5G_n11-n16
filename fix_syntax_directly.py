"""
一个更直接的方法来修复文件中的语法错误
"""

# 设置文件路径
filepath = r"h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02_1515.py"

# 读取文件内容
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

# 查找和修复问题 - 使用行号直接定位
line_num = 2244 - 1  # Python索引从0开始，所以第2244行对应索引2243
if line_num < len(lines):
    current_line = lines[line_num]
    if "except Exception as e:" in current_line and current_line.strip().startswith("except"):
        print(f"找到问题行: {current_line.strip()}")
        
        # 查找向上可以插入try语句的位置
        insert_line = -1
        for i in range(line_num-1, max(0, line_num-50), -1):
            if "if headers_frame_idx >= 0:" in lines[i]:
                insert_line = i + 1
                break
        
        if insert_line != -1:
            print(f"将在第{insert_line+1}行插入try语句")
            
            # 创建修复后的内容
            fixed_lines = lines[:insert_line]
            fixed_lines.append(lines[insert_line].rstrip() + " try:\n")  # 添加try语句
            
            # 添加中间行并调整缩进
            for i in range(insert_line+1, line_num):
                if lines[i].strip():  # 不是空行
                    fixed_lines.append("    " + lines[i])  # 添加额外的缩进
                else:
                    fixed_lines.append(lines[i])
            
            # 对问题行调整缩进
            fixed_lines.append(lines[line_num])
            
            # 添加剩余行
            fixed_lines.extend(lines[line_num+1:])
            
            # 写回文件
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(fixed_lines)
            
            print("文件已成功修复")
        else:
            print("未找到合适的位置插入try语句")
    else:
        print(f"第{line_num+1}行不包含预期的except语句")
else:
    print(f"文件只有{len(lines)}行")

# 检查另一种可能的问题模式 - 缩进问题
for i in range(2240, 2250):
    if i < len(lines) and "except Exception as e:" in lines[i]:
        if lines[i].strip().startswith("except") and i > 0:
            # 检查缩进
            prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
            curr_indent = len(lines[i]) - len(lines[i].lstrip())
            
            if curr_indent < prev_indent:
                print(f"在第{i+1}行发现缩进问题")
                # 修复缩进
                lines[i] = ' ' * prev_indent + lines[i].lstrip()
                
                # 同时修复下一行的缩进
                if i+1 < len(lines):
                    lines[i+1] = ' ' * (prev_indent + 4) + lines[i+1].lstrip()
                
                # 写回文件
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                
                print("已修复缩进问题")
                break
