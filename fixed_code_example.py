"""
这个文件包含了第2026行的修复代码。
该行有语法错误，两个if语句连续，没有正确的缩进。
以下是修复后的代码：
"""

# 错误行的上下文
for pattern_str in url_patterns:
    pattern = re.compile(pattern_str)
    for match in pattern.finditer(load):
        old_url = match.group(0)
        # 修复后的代码 - 注意嵌套if的正确缩进
        if b'/pdu-sessions/' in old_url:
            if b'http://' in old_url:
                new_url = f"http://{auth1}/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()
            else:
                new_url = f"/nsmf-pdusession/v1/pdu-sessions/{context_ID}".encode()
        location_patterns.append((old_url, new_url))

"""
要修复原始文件，需要手动把第2026行的代码替换为上面的正确格式，
确保第一个if语句和第二个if语句之间有适当的换行和缩进。

具体来说，应该将：
if b'/pdu-sessions/' in old_url:                    if b'http://' in old_url:

替换为：
if b'/pdu-sessions/' in old_url:
                    if b'http://' in old_url:

这样就解决了语法错误。
"""
