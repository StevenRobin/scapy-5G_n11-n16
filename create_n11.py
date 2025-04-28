from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet, bind_layers
import ipaddress
import string


# 自定义5G NAS层基础协议（简化的实现）
class NAS5G(Packet):
    name = "NAS5G"
    fields_desc = [
        ByteField("protocol_discriminator", 0x7e),
        ByteField("security_header_type", 0),
        ByteEnumField("message_type", 0x41, {
            0x41: "PDU Session Establishment Request",
            0x42: "PDU Session Modification Request",
            0x43: "PDU Session Release Request"
        }),
        # 其他字段根据具体消息类型扩展
        IPField("pdu_address", "0.0.0.0"),
        IntField("uplink_teid", 0),
        IntField("downlink_teid", 0)
    ]


# 参数生成器类
class ParamGenerator:
    def __init__(self):
        self.imsi_base = 123456789000001
        self.imei_base = 123456789012345
        self.msisdn_base = 886912345678
        self.cgi_base = 123456
        self.dnn_base = "dnn001"
        self.ipv4_base = ipaddress.IPv4Address("10.0.0.1")
        self.teid_base = 0x10000000
        self.amf_ip = ipaddress.IPv4Address("192.168.0.1")
        self.smf_ip = ipaddress.IPv4Address("192.168.1.1")
        self.session_count = 0

    def _increment_dnn(self, dnn):
        return ''.join(chr(ord(c) + 1) for c in dnn)

    def next_session(self):
        self.session_count += 1
        return {
            "imsi": str(self.imsi_base + self.session_count),
            "imei": str(self.imei_base + self.session_count),
            "msisdn": str(self.msisdn_base + self.session_count),
            "cgi": str(self.cgi_base + self.session_count),
            "dnn": self._increment_dnn(self.dnn_base),
            "pdu_ip": str(self.ipv4_base + self.session_count),
            "uplink_teid": self.teid_base + self.session_count * 2,
            "downlink_teid": self.teid_base + self.session_count * 2 + 1,
            "amf_ip": str(self.amf_ip + self.session_count),
            "smf_ip": str(self.smf_ip + self.session_count)
        }


# TCP流生成器
class TCPFlowGenerator:
    def __init__(self):
        self.seq_base = 1000
        self.sport = 38412
        self.dport = 80

    def _tcp_handshake(self, src_ip, dst_ip):
        syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.seq_base)
        syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=self.dport, dport=self.sport, flags="SA", seq=0,
                                                   ack=self.seq_base + 1)
        ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq_base + 1,
                                               ack=1)
        return [syn, syn_ack, ack]

    def _tcp_close(self, src_ip, dst_ip):
        fin_ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=self.sport, dport=self.dport, flags="FA",
                                                   seq=self.seq_base + 2, ack=1)
        ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=self.dport, dport=self.sport, flags="A", seq=1,
                                               ack=self.seq_base + 3)
        return [fin_ack, ack]


# PDU会话流程生成器
class PDUSessionGenerator:
    def __init__(self):
        self.param_gen = ParamGenerator()
        self.flow_gen = TCPFlowGenerator()
        self.packets = []

    def _generate_nas_message(self, msg_type, params):
        return NAS5G(
            message_type=msg_type,
            pdu_address=params["pdu_ip"],
            uplink_teid=params["uplink_teid"],
            downlink_teid=params["downlink_teid"]
        )

    def generate_establishment(self, params):
        # TCP握手
        self.packets.extend(self.flow_gen._tcp_handshake(params["amf_ip"], params["smf_ip"]))

        # NAS消息
        nas_msg = self._generate_nas_message(0x41, params)
        payload = IP(src=params["amf_ip"], dst=params["smf_ip"]) / TCP() / nas_msg
        self.packets.append(payload)

    def generate_modification(self, params):
        # NAS修改请求
        nas_msg = self._generate_nas_message(0x42, params)
        payload = IP(src=params["amf_ip"], dst=params["smf_ip"]) / TCP() / nas_msg
        self.packets.append(payload)

    def generate_release(self, params):
        # NAS释放请求
        nas_msg = self._generate_nas_message(0x43, params)
        payload = IP(src=params["amf_ip"], dst=params["smf_ip"]) / TCP() / nas_msg
        self.packets.append(payload)

        # TCP挥手
        self.packets.extend(self.flow_gen._tcp_close(params["amf_ip"], params["smf_ip"]))

    def generate_full_session(self):
        params = self.param_gen.next_session()
        self.generate_establishment(params)
        self.generate_modification(params)
        self.generate_release(params)
        return self.packets


# 主程序
if __name__ == "__main__":
    generator = PDUSessionGenerator()

    # 生成3个完整会话
    for _ in range(3):
        packets = generator.generate_full_session()

    # 保存为pcap文件
    wrpcap("n11_interface_traffic.pcap", packets)