from scapy.all import rdpcap, wrpcap, Raw
from hpack import Decoder, Encoder
import json

# 输入和输出文件路径
input_pcap = "pcap/N16_create_16p.pcap"
output_pcap = "pcap/N16_create_16p_mod01.pcap"

# 替换规则
replacements = {
    "supi": "imsi-46003010000002",
    "pei": "imeisv-1031014000012222",
    "gpsi": "msisdn-8615910012222",
    "ueIpv4Address": "100.0.0.1",
    "cnTunnelInfo": [
        {"ipv4Addr": "10.0.0.1", "gtpTeid": "A0000001"},
        {"ipv4Addr": "20.0.0.1", "gtpTeid": "B0000001"}
    ]
}

# 初始化 HPACK 解码器和编码器
decoder = Decoder()
encoder = Encoder()

# 读取 pcap 文件
packets = rdpcap(input_pcap)
modified_packets = []

for packet in packets:
    if Raw in packet:  # 检查是否包含 Raw 层
        raw_data = packet[Raw].load

        try:
            # 尝试解码 HPACK 数据
            decoded_headers = decoder.decode(raw_data)
            for header in decoded_headers:
                if isinstance(header, tuple) and header[1].startswith("{"):
                    json_data = json.loads(header[1])

                    # 更新 JSON 数据
                    for key, value in replacements.items():
                        if key in json_data:
                            json_data[key] = value
                        elif key == "cnTunnelInfo" and "cnTunnelInfo" in json_data:
                            json_data["cnTunnelInfo"] = value

                    # 重新编码为 HPACK
                    encoded_json = encoder.encode(header[0], json.dumps(json_data))
                    packet[Raw].load = encoded_json
                    break  # 停止搜索 JSON 数据

        except Exception as e:
            # 如果解码失败，则跳过
            pass

    # 将修改后的包添加到新包列表
    modified_packets.append(packet)

# 写入修改后的 pcap 文件
wrpcap(output_pcap, modified_packets)

print(f"修改后的报文已保存到 {output_pcap}")