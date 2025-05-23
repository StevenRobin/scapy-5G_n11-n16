"""
简化版本的修复脚本，修复try块缺少except块的语法错误
"""

def fix_missing_except():
    file_path = r'h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02.py'
    
    try:
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # 创建备份
        with open(file_path + '.bak', 'w', encoding='utf-8') as f:
            f.write(content)
            
        # 找到第1655-1710行左右的try块并添加缺失的except块
        start_pattern = 'try:\n                # 获取可能已修改的原始负载'
        end_pattern = '        # 第二轮：处理DATA帧和content-length'
        
        if start_pattern in content and end_pattern in content:
            fixed_content = content.replace(
                end_pattern,
                '            except Exception as e:\n                logger.error(f"处理第{idx}个报文帧提取错误: {str(e)}")\n                logger.error(traceback.format_exc())\n                continue\n\n' + end_pattern
            )
            
            # 写入修复后的内容
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
                
            print(f"已修复{file_path}中缺失的except块")
            return True
        else:
            print("未找到目标代码块")
            return False
            
    except Exception as e:
        print(f"修复过程出错: {str(e)}")
        return False

if __name__ == "__main__":
    fix_missing_except()
