from scapy.all import *
from scapy.packet import Packet
from scapy.fields import ByteField, IntField, BitField, StrLenField
from hpack import Encoder, Decoder
import json
from email.parser import Parser
from email.policy import HTTP


class HTTP2FrameHeader(Packet):
    name = "HTTP2FrameHeader"
    fields_desc = [
        BitField("length", 0, 24),
        ByteField("type", 0),
        ByteField("flags", 0),
        BitField("r", 0, 1),
        BitField("stream_id", 0, 31)
    ]

    def post_build(self, pkt, pay):
        length = len(pay)
        frame_header = length.to_bytes(3, byteorder='big') + bytes([self.type, self.flags]) + self.stream_id.to_bytes(4,
                                                                                                                      byteorder='big')
        return frame_header + pay


class HTTP2HeadersFrame(Packet):
    name = "HTTP2HeadersFrame"
    fields_desc = [
        StrLenField("header_block_fragment", "", length_from=lambda pkt: pkt.underlayer.length)
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encoder = Encoder()
        self.decoder = Decoder()

    def add_headers(self, headers, stream_id=1, flags=0x4):
        """
        添加压缩后的头部到 HEADERS 帧
        :param headers: 字典形式的头部，例如 {':method': 'GET', ':path': '/'}
        :param stream_id: 流标识符
        :param flags: 标志位（例如，0x4 表示 END_HEADERS）
        """
        # 使用 HPACK 进行编码
        header_block = self.encoder.encode(headers)
        # 设置 header_block_fragment
        self.header_block_fragment = header_block
        # 创建帧头
        frame_header = HTTP2FrameHeader(type=0x1, flags=flags, stream_id=stream_id)
        # 组装帧
        return frame_header / self

    def extract_headers(self):
        """
        从头部块中解码出头部字段
        :return: 字典形式的头部
        """
        decoded_headers = self.decoder.decode(self.header_block_fragment)
        return decoded_headers


class HTTP2Packet(Packet):
    name = "HTTP2Packet"
    fields_desc = []

    def add_headers_frame(self, headers, stream_id=1, flags=0x4):
        headers_frame = HTTP2HeadersFrame()
        headers_frame.add_headers(headers, stream_id=stream_id, flags=flags)
        self /= headers_frame
        return self

    def extract_headers_frame(self):
        headers_frames = self.getlayer(HTTP2HeadersFrame)
        if headers_frames:
            return headers_frames.extract_headers()
        return {}


# 定义 HTTP2 协议层（与上述相同）

# 假设 PCAP 文件名为 'decrypted_http2_5g.pcap'
pcap_filename = "d:\\3333.pcap"

# 读取 PCAP 文件
packets = rdpcap(pcap_filename)

# 定义 IMSI 关键字，根据实际情况调整
IMSI_KEYWORD = "supi"
k2 = "location"


def parse_and_modify_pcap(packets, new_imsi):
    for pkt in packets:
        if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
            tcp_payload = bytes(pkt["Raw"].load)
            offset = 0

            # 处理所有 HTTP/2 帧
            while offset + 9 <= len(tcp_payload):
                frame_header = HTTP2FrameHeader(tcp_payload[offset:offset + 9])
                frame_type = frame_header.type
                frame_length = frame_header.length
                stream_id = frame_header.stream_id

                if offset + 9 + frame_length > len(tcp_payload):
                    break

                frame_payload = tcp_payload[offset + 9:offset + 9 + frame_length]

                if frame_type == 0x1:  # HEADERS Frame
                    headers_frame = HTTP2HeadersFrame(header_block_fragment=frame_payload)
                    decoded_headers = headers_frame.extract_headers()

                    imsi_key = None
                    auth = None
                    idx = 0
                    for key in decoded_headers:
                        if k2 == key[0]:
                            imsi_key = key
                            break
                        idx += 1

                    if auth:
                        print(f"找到 auth 字段: {auth} = {decoded_headers[idx]}")
                        decoded_headers[idx] = (":authority", "123.1.1.11")
                        print(f"修改后的 auth 字段: {auth} = {decoded_headers[idx]}")
                    if imsi_key:
                        print(f"找到 IMSI 字段: {imsi_key} = {decoded_headers[idx]}")
                        decoded_headers[idx] = (
                        k2, "http://123.1.1.10/nsmf-pdusession/v1/sm-contexts/imsi-460030100000011-5")
                        print(f"修改后的 IMSI 字段: {imsi_key} = {decoded_headers[idx]}")

                        # 重新编码头部
                        encoder = Encoder()
                        new_header_block = encoder.encode(decoded_headers)

                        # 重新构建帧头
                        new_frame_header = HTTP2FrameHeader(length=frame_header.length,
                                                            type=0x1,
                                                            r=frame_header.r,
                                                            flags=frame_header.flags,
                                                            stream_id=stream_id)

                        # 构建新的 TCP 载荷
                        # new_tcp_payload = bytes(new_frame_header) + new_header_block
                        new_tcp_payload = tcp_payload[offset:offset + 9] + new_header_block

                        # 保留未修改部分的数据包载荷（如果有）
                        remaining_payload = tcp_payload[9 + frame_length:]
                        pkt[Raw].load = new_tcp_payload + remaining_payload

                        # 重新计算校验和
                        del pkt["IP"].len
                        del pkt["IP"].chksum
                        del pkt["TCP"].chksum
                        modified_pcap = "d:\\3333_out.pcap"
                        wrpcap(modified_pcap, packets)
                        return

                elif frame_type == 0x3:  # DATA Frame
                    # 需要判断 boundary
                    if frame_payload.startswith(b"--++Boundary\r\nContent-Type:application/json\r\n\r\n"):
                        # 跳过头部
                        start_pos = len(b"--++Boundary\r\nContent-Type:application/json\r\n\r\n")
                        # 寻找下一个边界或\r\n
                        next_boundary = frame_payload.find(b"--++Boundary", start_pos)
                        next_crlf = frame_payload.find(b"\r\n", start_pos)

                        if next_boundary != -1 and (next_crlf == -1 or next_boundary < next_crlf):
                            frame_payload = frame_payload[start_pos:next_boundary]
                        elif next_crlf != -1:
                            frame_payload = frame_payload[start_pos:next_crlf]
                        else:
                            frame_payload = frame_payload[start_pos:]

                        try:
                            # 尝试解析 JSON 数据
                            json_data = json.loads(frame_payload)
                            if isinstance(json_data, dict):
                                # 在 JSON 中查找 IMSI
                                for key, value in json_data.items():
                                    if IMSI_KEYWORD.lower() in str(key).lower():
                                        print(f"在 DATA 帧中找到 IMSI 字段: {key} = {value}")
                                        json_data[key] = new_imsi
                                        print(f"修改后的 IMSI 字段: {key} = {json_data[key]}")

                                        # 更新 JSON 内容
                                        new_json = json.dumps(json_data).encode()

                                        # 更新 DATA 帧
                                        new_data_frame = HTTP2FrameHeader(
                                            type=0x0,
                                            flags=frame_header.flags,
                                            stream_id=stream_id,
                                            length=len(new_json)
                                        )
                                        new_data = bytes(new_data_frame) + new_json

                                        # 更新 TCP 载荷
                                        tcp_payload = tcp_payload[:offset] + new_data + tcp_payload[
                                                                                        offset + 9 + frame_length:]
                        except json.JSONDecodeError:
                            # 如果不是 JSON，尝试查找 IMSI 字符串
                            try:
                                payload_str = frame_payload.decode('utf-8')
                                if IMSI_KEYWORD.lower() in payload_str.lower():
                                    print(f"在 DATA 帧中找到 IMSI 字符串")
                                    # 这里可以根据具体格式进行字符串替换
                                    # 例如：new_payload = payload_str.replace(old_imsi, new_imsi)
                                    # 然后更新帧内容
                            except UnicodeDecodeError:
                                print("无法解码 DATA 帧内容")
                                pass

                # 移动到下一个帧
                offset += 9 + frame_length

            # 更新包的 Raw 载荷
            pkt[Raw].load = tcp_payload

    # 保存修改后的 PCAP
    modified_pcap = "d:\\3333_out.pcap"
    wrpcap(modified_pcap, packets)
    print(f"已保存修改后的 PCAP 文件为 {modified_pcap}")


# 示例：修改 IMSI 为 '123456789012345'
new_imsi = "imsi-460030100000011"
parse_and_modify_pcap(packets, new_imsi)