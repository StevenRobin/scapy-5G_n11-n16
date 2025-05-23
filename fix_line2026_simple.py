"""
一个非常简单的程序，专门修复n16_test_fixed02_1515.py文件的第2026行语法错误
"""

# 读取文件
filepath = r"h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02_1515.py"

# 读取所有行
with open(filepath, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

# 检查文件行数
if len(lines) < 2026:
    print(f"文件只有{len(lines)}行，不包含第2026行")
    exit(1)

# 获取并显示第2026行（索引为2025）
problem_line = lines[2025]
print(f"原始第2026行: {problem_line}")

# 检测问题模式并修复
if "if b'/pdu-sessions/' in old_url:" in problem_line and "if b'http://'" in problem_line:
    # 分割字符串并添加换行和缩进
    parts = problem_line.split("if b'http://'", 1)
    fixed_line = parts[0] + "\n                    if b'http://'" + parts[1]
    lines[2025] = fixed_line
    print("已修复行 (单引号版本)")
elif 'if b"/pdu-sessions/" in old_url:' in problem_line and 'if b"http://"' in problem_line:
    # 分割字符串并添加换行和缩进
    parts = problem_line.split('if b"http://"', 1)
    fixed_line = parts[0] + '\n                    if b"http://"' + parts[1]
    lines[2025] = fixed_line
    print("已修复行 (双引号版本)")
else:
    # 更一般的替换
    fixed_line = problem_line.replace(": ", ":\n                    ", 1)
    if fixed_line != problem_line:
        lines[2025] = fixed_line
        print("已使用一般方法修复行")
    else:
        print("无法识别错误模式，未修复")
        exit(1)

# 写回文件
with open(filepath, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("文件已保存，修复完成")
