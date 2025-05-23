"""
直接修复特定行
"""

def fix_specific_lines():
    try:
        # 指定需要修复的特定行号
        problem_lines = [2026, 2873]  # 基于错误消息和grep查询结果
        file_path = "n16_test_fixed02_1515.py"
        
        # 读取所有行
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            
        # 逐行检查和修复
        fixed_count = 0
        for i in problem_lines:
            if i <= len(lines):
                line_idx = i - 1  # 转换为0-based索引
                if "if b'/pdu-sessions/' in old_url:" in lines[line_idx] and "if b'http://' in old_url:" in lines[line_idx]:
                    parts = lines[line_idx].split("if b'http://'")
                    lines[line_idx] = parts[0] + "\n                    if b'http://'" + parts[1]
                    fixed_count += 1
                    print(f"已修复第{i}行")
        
        # 如果有修复，则写回文件
        if fixed_count > 0:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            print(f"共修复了 {fixed_count} 处错误")
        else:
            print("未找到需要修复的错误")
            
    except Exception as e:
        print(f"处理时发生错误: {e}")

if __name__ == "__main__":
    fix_specific_lines()
