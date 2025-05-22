"""
修复文件中所有匹配错误模式的行
"""
import re

def main():
    filepath = "h:\\pythonProject\\study_01\\scapy-5G_n11-n16\\n16_test_fixed02_1515.py"
    
    try:
        # 读取文件内容
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        # 查找有问题的行的模式
        pattern = r"if b'/pdu-sessions/' in old_url:\s+if b'http://'"
        
        # 创建替换后的内容
        fixed_content = re.sub(pattern, 
                              "if b'/pdu-sessions/' in old_url:\n                    if b'http://'", 
                              content)
        
        # 检查是否有修改
        if fixed_content != content:
            # 写回文件
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            print(f"已修复文件, 找到并替换了 {content.count('if b\'/pdu-sessions/\' in old_url:                    if b\'http://\'')} 处错误")
        else:
            print("未找到需要修复的内容")
        
    except Exception as e:
        print(f"处理文件时发生错误: {e}")

if __name__ == "__main__":
    main()
