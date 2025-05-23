import os
import re

def main():
    source_file = "n16_test_fixed02_1515.py"
    temp_file = "temp_fixed.py"
    target_line = 2026  # 目标行
    
    # 确保源文件存在
    if not os.path.exists(source_file):
        print(f"错误: 源文件 '{source_file}' 不存在")
        return False
    
    try:
        # 读取文件内容并修复特定行
        with open(source_file, 'rb') as f:
            lines = f.readlines()
        
        if len(lines) < target_line:
            print(f"文件只有 {len(lines)} 行，不包含第 {target_line} 行")
            return False
            
        # 获取需要修复的行 (索引从0开始，所以2026行是索引2025)
        problem_line = lines[target_line-1]
        
        print(f"正在处理第 {target_line} 行: {problem_line}")
        
        # 创建修复后的行 - 这里我们将空格+if替换为换行+缩进+if
        fixed_line = re.sub(rb':\s+if', b':\n                    if', problem_line)
        
        # 如果有修改，则应用修改
        if fixed_line != problem_line:
            lines[target_line-1] = fixed_line
            print("已修复问题行")
            
            # 写入临时文件
            with open(temp_file, 'wb') as f:
                f.writelines(lines)
                
            print(f"修复后的内容已写入临时文件 '{temp_file}'")
            print(f"请检查临时文件，然后手动替换原始文件或运行以下命令:")
            print(f"import os; os.replace('{temp_file}', '{source_file}')")
        else:
            print("未能识别行中的错误模式")
            return False
            
        return True
    
    except Exception as e:
        print(f"处理文件时发生错误: {e}")
        return False

if __name__ == "__main__":
    main()
