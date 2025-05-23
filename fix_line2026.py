import re
import os

def fix_file(filepath):
    print(f"尝试修复文件: {filepath}")
    
    # 检查文件是否存在
    if not os.path.exists(filepath):
        print(f"错误: 文件 '{filepath}' 不存在")
        return False
    
    try:
        # 读取文件内容，按行读取，以便精确定位问题行
        with open(filepath, 'rb') as f:
            lines = f.readlines()
            
        print(f"成功读取文件，共 {len(lines)} 行")
        
        # 处理第2026行 (索引为2025)
        if len(lines) > 2025:
            line = lines[2025]
            print(f"第2026行内容: {line}")
            
            # 检查是否包含连续的if语句
            if b"if b'/pdu-sessions/'" in line and b"if b'http://'" in line:
                parts = line.split(b"if b'http://'", 1)
                fixed_line = parts[0] + b"\n                    if b'http://'" + parts[1]
                lines[2025] = fixed_line
                print("已修复行 (单引号版本)")
                fixed = True
            elif b'if b"/pdu-sessions/"' in line and b'if b"http://"' in line:
                parts = line.split(b'if b"http://"', 1)
                fixed_line = parts[0] + b'\n                    if b"http://"' + parts[1]
                lines[2025] = fixed_line
                print("已修复行 (双引号版本)")
                fixed = True
            else:
                print("未找到期望的错误模式，尝试更一般的方式...")
                
                # 更一般的方式查找和替换
                if b"if b" in line and b"pdu-sessions" in line and b"http://" in line:
                    colon_pos = line.find(b":", 20)  # 找到第一个冒号的位置
                    if colon_pos > 0 and colon_pos + 15 < len(line) and b"if" in line[colon_pos+1:colon_pos+20]:
                        fixed_line = line[:colon_pos+1] + b"\n                    " + line[colon_pos+1:].lstrip()
                        lines[2025] = fixed_line
                        print("已使用一般方法修复行")
                        fixed = True
                    else:
                        fixed = False
                else:
                    fixed = False
                
            if fixed:
                # 写回文件
                with open(filepath, 'wb') as f:
                    f.writelines(lines)
                print("文件已成功修复并保存")
                return True
            else:
                print("未能修复第2026行，未找到预期的错误模式")
        else:
            print(f"文件行数不足，只有 {len(lines)} 行")
            
        return False
            
    except Exception as e:
        print(f"修复过程中发生错误: {e}")
        return False

if __name__ == "__main__":
    filepath = r"h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02_1515.py"
    fix_file(filepath)
