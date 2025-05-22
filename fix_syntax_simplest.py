"""
最简单直接的方法修复文件中的语法错误
"""

# 文件路径
filepath = r"h:\pythonProject\study_01\scapy-5G_n11-n16\n16_test_fixed02_1515.py"

# 读取文件内容
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# 替换问题区域
problem_text = '''                    # 直接返回新创建的帧数据
                    return new_frame_data
                
                    except Exception as e:
                    logger.error(f"硬编码HPACK处理失败: {e}")
                    import traceback
                    logger.error(traceback.format_exc())'''

fixed_text = '''                    # 直接返回新创建的帧数据
                    return new_frame_data
                
                except Exception as e:
                    logger.error(f"硬编码HPACK处理失败: {e}")
                    import traceback
                    logger.error(traceback.format_exc())'''

# 进行替换
if problem_text in content:
    fixed_content = content.replace(problem_text, fixed_text)
    
    # 写回文件
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    
    print("文件已成功修复")
else:
    print("未找到问题代码段")
