"""
创建一个修复后的副本，并将其复制回原始文件
"""
import os
import shutil

def main():
    original_file = "n16_test_fixed02_1515.py"
    fixed_file = "n16_test_fixed02_1515_fixed.py"
    
    # 确定我们在正确的目录
    print(f"当前工作目录: {os.getcwd()}")
    if not os.path.exists(original_file):
        print(f"错误: 找不到原始文件 {original_file}")
        return
    
    # 读取原始文件
    with open(original_file, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    # 修复所有实例
    fixed_count = 0
    for i, line in enumerate(lines):
        if "if b'/pdu-sessions/' in old_url:" in line and "if b'http://'" in line and "if b'/pdu-sessions/' in old_url:                    if b'http://'" in line:
            # 处理单引号版本
            old_text = "if b'/pdu-sessions/' in old_url:                    if b'http://'"
            new_text = "if b'/pdu-sessions/' in old_url:\n                    if b'http://'"
            lines[i] = line.replace(old_text, new_text)
            fixed_count += 1
            print(f"修复了第 {i+1} 行")
        elif 'if b"/pdu-sessions/" in old_url:' in line and 'if b"http://"' in line and 'if b"/pdu-sessions/" in old_url:                    if b"http://"' in line:
            # 处理双引号版本
            old_text = 'if b"/pdu-sessions/" in old_url:                    if b"http://"'
            new_text = 'if b"/pdu-sessions/" in old_url:\n                    if b"http://"'
            lines[i] = line.replace(old_text, new_text)
            fixed_count += 1
            print(f"修复了第 {i+1} 行")
    
    if fixed_count > 0:
        # 保存到新文件
        with open(fixed_file, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f"已创建修复后的文件: {fixed_file}")
        
        # 创建原始文件的备份
        backup_file = original_file + ".bak"
        shutil.copy2(original_file, backup_file)
        print(f"已创建备份文件: {backup_file}")
        
        # 将修复后的文件复制回原始文件
        shutil.copy2(fixed_file, original_file)
        print(f"已将修复后的文件复制回原始文件")
    else:
        print("未找到需要修复的内容")

if __name__ == "__main__":
    main()
