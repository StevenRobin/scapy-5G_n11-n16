"""
使用正则表达式修复所有行
"""
import re
import os

def fix_file():
    input_path = r"h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02_1515.py"
    temp_path = r"h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02_1515_fixed.py"
    
    if os.path.exists(input_path):
        print(f"找到源文件: {input_path}")
        
        try:
            # 读取原始文件内容
            with open(input_path, 'rb') as f:
                content = f.read()
                
            # 查找并替换有问题的行
            # 将 `: [spaces] if` 替换为 `:\n[spaces] if`
            fixed_content = re.sub(
                rb'(if\s+b[\'"]/pdu-sessions/[\'"].*?in\s+old_url:)\s+(if\s+b[\'"](http://)[\'"].*?in\s+old_url:)', 
                rb'\1\n                    \2', 
                content
            )
            
            # 写入临时文件
            with open(temp_path, 'wb') as f:
                f.write(fixed_content)
                
            print(f"已创建修复后的文件: {temp_path}")
            print("请检查临时文件是否正确，然后将其复制回原始文件")
            
            # 比较原始内容和修复后内容
            if content != fixed_content:
                print("文件内容已被修改")
            else:
                print("警告：文件内容未发生变化，可能未找到错误模式")
                
        except Exception as e:
            print(f"处理文件时发生错误: {e}")
    else:
        print(f"找不到源文件: {input_path}")

if __name__ == "__main__":
    fix_file()
