"""
使用字符串下标精确定位并修复语法错误
"""
import sys

def main():
    file_path = "n16_test_fixed02_1515.py"
    line_number = 2026  # 行号 (从1开始)
    
    try:
        # 读取整个文件内容
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        # 将文件内容按行分割
        lines = content.split('\n')
        
        # 检查行数
        if len(lines) < line_number:
            print(f"文件只有 {len(lines)} 行")
            return False
            
        # 获取问题行 (索引从0开始)
        problem_line = lines[line_number - 1]
        print(f"原始问题行: {problem_line}")
        
        # 定位和修复缺少换行的地方
        if ': ' in problem_line and 'if ' in problem_line[problem_line.find(': ')+2:]:
            # 找到第一个冒号后面的if
            colon_pos = problem_line.find(': ')
            if_pos = problem_line.find('if ', colon_pos)
            
            # 在冒号后添加换行和缩进
            if if_pos > colon_pos:
                fixed_line = problem_line[:colon_pos+1] + '\n                    ' + problem_line[if_pos:]
                lines[line_number - 1] = fixed_line
                print(f"修复后的行: {fixed_line}")
                
                # 写回文件
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines))
                print("文件已成功修复")
                return True
            else:
                print("未找到预期的错误模式")
        else:
            print("行中没有找到预期的冒号和if模式")
            
        return False
    
    except Exception as e:
        print(f"发生错误: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
