"""
专门修复文件中的except语法错误 - 针对第2244行
"""
import re

def fix_specific_line():
    filepath = r"h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02_1515.py"
    
    # 读取文件
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # 查找问题代码段
    pattern = r"(# 直接返回新创建的帧数据\s+return new_frame_data\s+)\s+except Exception as e:"
    
    # 替换为正确的语法
    fixed_content = re.sub(pattern, 
                          r"\1except Exception as e:", 
                          content)
    
    # 写回文件
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
        
    print("文件修复完成")

if __name__ == "__main__":
    fix_specific_line()
