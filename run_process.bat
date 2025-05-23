@echo off
REM 这是一个批处理文件，用来执行我们的处理和验证
echo 开始处理PCAP文件...
python n16_test_fixed02.py -i pcap\N16_create_16p.pcap -o pcap\N16_fixed_pkt15.pcap
if %ERRORLEVEL% NEQ 0 (
    echo 处理PCAP文件失败！
    exit /b 1
)
echo PCAP处理完成！

echo 验证处理结果...
python verify_pkt15.py pcap\N16_fixed_pkt15.pcap
if %ERRORLEVEL% NEQ 0 (
    echo 验证失败！
    exit /b 1
)
echo 验证完成！

echo 整个处理和验证过程成功完成！
