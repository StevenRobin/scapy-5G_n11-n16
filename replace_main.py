"""
用修复后的main函数替换n16_test_fixed02.py中的main函数
"""
import os
import re

def replace_main_function():
    try:
        # 读取修复后的main函数
        with open('fixed_main.py', 'r', encoding='utf-8') as f:
            fixed_main = f.read()
        
        # 读取原始文件
        with open('n16_test_fixed02.py', 'r', encoding='utf-8', errors='ignore') as f:
            original = f.read()
        
        # 创建备份
        with open('n16_test_fixed02.py.bak2', 'w', encoding='utf-8') as f:
            f.write(original)
        
        # 查找原始main函数的起始位置
        main_start_pattern = r'def main\(\):'
        main_start_match = re.search(main_start_pattern, original)
        
        if not main_start_match:
            print("找不到main函数的起始位置")
            return False
        
        # 查找原始main函数的结束位置
        main_start_pos = main_start_match.start()
        remaining_text = original[main_start_pos:]
        
        # 检查if __name__ == "__main__":的位置
        if_main_pattern = r'if __name__ == "__main__":'
        if_main_match = re.search(if_main_pattern, remaining_text)
        
        if if_main_match:
            main_end_pos = main_start_pos + if_main_match.start()
            
            # 替换main函数
            new_content = original[:main_start_pos] + fixed_main + original[main_end_pos:]
            
            # 写入文件
            with open('n16_test_fixed02.py', 'w', encoding='utf-8') as f:
                f.write(new_content)
                
            print("成功替换main函数")
            return True
        else:
            print("找不到main函数的结束位置")
            return False
    
    except Exception as e:
        print(f"替换过程出错: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == "__main__":
    replace_main_function()
