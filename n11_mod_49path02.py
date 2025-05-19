#!/usr/bin/env python3
import subprocess
import os


def export_http2_decoded(pcap_file, output_file, packet_num=49):
    """
    使用tshark(Wireshark命令行)导出解码后的HTTP/2头部
    """
    # 构建tshark命令
    command = [
        'tshark',
        '-r', pcap_file,
        '-Y', f'frame.number == {packet_num}',
        '-T', 'fields',
        '-e', 'http2.header.path',
        '-o', 'http2.hpack_display:1'
    ]

    print(f"执行命令: {' '.join(command)}")

    try:
        # 执行命令并获取输出
        result = subprocess.run(command, capture_output=True, text=True)
        if result.stdout.strip():
            path = result.stdout.strip()
            print(f"找到解码后的路径: {path}")

            # 只替换SUPI部分
            if "imsi-460030100000000-5" in path:
                new_path = path.replace("imsi-460030100000000-5", "imsi-460031234567890-7")
                print(f"修改后的路径: {new_path}")

                # 这里你可以继续使用tshark编辑功能或保存结果
                with open(output_file, "w") as f:
                    f.write(f"Original Path: {path}\n")
                    f.write(f"Modified Path: {new_path}\n")
                print(f"保存结果到: {output_file}")
            else:
                print(f"路径中未找到预期的SUPI模式")
        else:
            print("未找到HTTP/2路径信息")
            if result.stderr:
                print(f"错误信息: {result.stderr}")
    except Exception as e:
        print(f"执行tshark时出错: {str(e)}")


if __name__ == "__main__":
    pcap_file = "pcap/N11_create_50p.pcap"
    output_file = "http2_path_modified.txt"
    export_http2_decoded(pcap_file, output_file)