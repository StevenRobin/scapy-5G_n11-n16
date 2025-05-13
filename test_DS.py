from scapy.all import rdpcap, IP, TCP, Raw
import hpack
import binascii
from collections import defaultdict

# 配置区
PCAP_PATH = "pcap/N16_create_16p.pcap"
TARGET_INDICES = [10, 12, 14]  # 第11、13、15个包


class StreamDecoder:
    """精准到流的HPACK解码器，支持RFC 7541完整特性"""

    def __init__(self):
        self.decoder = hpack.Decoder()
        self._current_table_size = 4096
        self._base_index = 0  # Post-Base索引基址

    def safe_decode(self, data):
        """带动态表错误恢复的解码"""
        try:
            # 预处理动态表更新指令
            clean_data = self._process_table_commands(data)
            return self.decoder.decode(clean_data)
        except hpack.exceptions.InvalidTableIndex as e:
            print(f"  动态表重置: {str(e)}")
            self._reset_decoder()
            return self.decoder.decode(data)  # 重试解码

    def _process_table_commands(self, data):
        """处理RFC 7541定义的动态表更新指令"""
        index = 0
        while index < len(data):
            byte = data[index]

            # 动态表尺寸更新 (6.3节)
            if (byte & 0xE0) == 0x20:
                new_size = byte & 0x1F
                index += 1
                # 处理多字节编码
                if new_size == 0x1F:
                    new_size = data[index]
                    index += 1
                self._apply_table_size(new_size)

            # Post-Base索引更新 (6.2节)
            elif (byte & 0x80) == 0x80:
                self._base_index = byte & 0x7F
                index += 1

            else:
                break  # 结束指令处理

        return data[index:]

    def _apply_table_size(self, new_size):
        """安全更新动态表尺寸"""
        new_size = min(new_size, 4096)  # 强制最大限制
        if new_size < self._current_table_size:
            self.decoder.apply_table_size(new_size)
        self._current_table_size = new_size

    def _reset_decoder(self):
        """完全重置解码器状态"""
        self.decoder = hpack.Decoder()
        self._current_table_size = 4096
        self._base_index = 0


def enhanced_analysis():
    # 初始化连接+流级别的解码器映射
    decoder_map = defaultdict(
        lambda: defaultdict(StreamDecoder)
    )

    try:
        packets = rdpcap(PCAP_PATH)
    except Exception as e:
        print(f"PCAP加载失败: {str(e)}")
        return

    for idx in TARGET_INDICES:
        if idx >= len(packets):
            print(f"包 {idx + 1} 不存在")
            continue

        pkt = packets[idx]
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            print(f"[#{idx + 1}] 非HTTP/2数据包")
            continue

        raw = pkt[Raw].load
        conn_id = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)

        print(f"\n[#{idx + 1}] 深度解析 ({len(raw)} bytes)")
        content_length = None
        index = 0

        while index < len(raw):
            try:
                # 解析HTTP/2帧头
                if index + 9 > len(raw):
                    break

                length = int.from_bytes(raw[index:index + 3], 'big')
                frame_type = raw[index + 3]
                stream_id = int.from_bytes(raw[index + 5:index + 9], 'big') & 0x7FFFFFFF
                frame_end = index + 9 + length
                frame_end = min(frame_end, len(raw))

                if frame_type == 0x01:  # HEADERS帧
                    decoder = decoder_map[conn_id][stream_id]
                    frame_data = raw[index + 9:frame_end]

                    headers = decoder.safe_decode(frame_data)
                    for k, v in headers:
                        if k.lower() == 'content-length':
                            content_length = v
                            break

                index = frame_end
            except Exception as e:
                print(f"  解析中断: {str(e)}")
                break

        print(f"  最终结果: {content_length or '未检测到'}")


if __name__ == "__main__":
    enhanced_analysis()