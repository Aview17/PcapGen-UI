"""
    TCP报文生成主逻辑
"""
import re

from scapy.all import *
from scapy.utils import wrpcap
from scapy.layers.inet import IP, TCP, Ether

from Tools import NetworkTools


def get_tcp_req_packet(all_tcp_request, syn_ack_packet, ack_packet, ip_src_pack, ip_dst_pack, src_port, dst_port, mtu=1460, add=0, add2=0):
    if len(all_tcp_request) < mtu + 1:
        tcp_req_one = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags=24, seq=ack_packet[TCP].seq + add,
                                      ack=syn_ack_packet[TCP].seq + 1 + add2)/all_tcp_request
        tcp_req_ack_one = ip_dst_pack/TCP(sport=dst_port, dport=src_port, seq=tcp_req_one[TCP].ack,
                                          ack=tcp_req_one[TCP].seq + len(all_tcp_request), flags='A')
        return [tcp_req_one], [tcp_req_ack_one]

    # 处理超过MTU的报文
    tcp_req_packet_list = []
    tcp_req_packet_ack_list = []
    group_num = math.ceil(len(all_tcp_request) / int(mtu))
    for i in range(group_num):
        fragment_req = all_tcp_request[i*mtu: i*mtu+mtu]
        if i == 0:
            fragment_req_pack = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags="A",
                                                seq=ack_packet[TCP].seq + add,
                                                ack=syn_ack_packet[TCP].seq + 1 + add2)/fragment_req
        else:
            fragment_req_pack = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags=24,
                                                seq=ack_packet[TCP].seq + i * mtu + add,
                                                ack=syn_ack_packet[TCP].seq + 1 + add2)/fragment_req
        # 每个请求包的ack包
        fragment_req_ack_pack = ip_dst_pack/TCP(sport=dst_port, dport=src_port, seq=fragment_req_pack[TCP].ack,
                                                ack=fragment_req_pack[TCP].seq + len(fragment_req), flags='A')
        tcp_req_packet_list.append(fragment_req_pack)
        # 分包情况下只留下对最后一个包的确认包
        if i == group_num - 1:
            tcp_req_packet_ack_list.append(fragment_req_ack_pack)

    return tcp_req_packet_list, tcp_req_packet_ack_list


def get_tcp_rsp_packet(all_tcp_response, last_check_ack_pack, ip_src_pack, ip_dst_pack, src_port, dst_port, mtu=1460):
    if len(all_tcp_response) < mtu + 1:
        tcp_rsp_one = ip_dst_pack/TCP(sport=src_port, dport=dst_port, flags=24, seq=last_check_ack_pack[TCP].seq,
                                      ack=last_check_ack_pack[TCP].ack)/all_tcp_response
        tcp_rsp_ack_one = ip_src_pack/TCP(sport=dst_port, dport=src_port, seq=tcp_rsp_one[TCP].ack,
                                          ack=tcp_rsp_one[TCP].seq + len(all_tcp_response), flags='A')
        return [tcp_rsp_one], [tcp_rsp_ack_one], len(all_tcp_response)

    # 处理超过mtu的响应体
    tcp_rsp_packet_list = []
    tcp_rsp_packet_ack_list = []
    group_num = math.ceil(len(all_tcp_response) / int(mtu))
    last_fragment_rsp_len = 0   # 最后一段响应体的长度
    for i in range(group_num):
        fragment_rsp = all_tcp_response[i*mtu: i*mtu+mtu]
        if i == group_num-1:
            last_fragment_rsp_len = len(fragment_rsp)
        if i == 0:
            fragment_rsp_pack = ip_dst_pack/TCP(sport=src_port, dport=dst_port, flags=24,
                                                seq=last_check_ack_pack[TCP].seq,
                                                ack=last_check_ack_pack[TCP].ack)/fragment_rsp
        else:
            fragment_rsp_pack = ip_dst_pack/TCP(sport=src_port, dport=dst_port, flags=24,
                                                seq=last_check_ack_pack[TCP].seq + i * mtu,
                                                ack=last_check_ack_pack[TCP].ack)/fragment_rsp

        # 每个响应包的ack包
        fragment_rsp_ack_pack = ip_src_pack/TCP(sport=dst_port, dport=src_port, seq=fragment_rsp_pack[TCP].ack,
                                                ack=fragment_rsp_pack[TCP].seq + len(fragment_rsp), flags='A')

        tcp_rsp_packet_list.append(fragment_rsp_pack)
        # 分包情况下只留下对最后一个包的确认包
        if i == group_num - 1:
            tcp_rsp_packet_ack_list.append(fragment_rsp_ack_pack)

    return tcp_rsp_packet_list, tcp_rsp_packet_ack_list, last_fragment_rsp_len


def create_tcp_pcap(req_content_list, rsp_content_list, save_path, tdp_four_tuple):
    # 先判断一下请求/响应是否合规
    verify_res = verify_tcp_req_rsp(req_content_list, rsp_content_list)
    if not verify_res["success"]:
        verify_res["level"] = "error"
        return verify_res

    # 获取四元组
    src_ip = tdp_four_tuple["sip"]
    src_port = tdp_four_tuple["sport"]
    dst_ip = tdp_four_tuple["dip"]
    dst_port = tdp_four_tuple["dport"]

    # 每次生成pcap时都使用随机生成的单播mac地址
    src_mac = NetworkTools.generate_mac_address()
    dst_mac = NetworkTools.generate_mac_address()

    ''' 以下为生成报文的步骤 ------------------------------------------------------------------------------------------'''
    # 首先生成请求响应的IP层包
    ip_src_pack = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, flags="DF")
    ip_dst_pack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ip, dst=src_ip, flags="DF")

    # 设置请求响应包的SEQ
    seq_req = random.randint(3000000000, 4000000000)
    seq_rsp = random.randint(2000000000, 3000000000)

    # 初始化全包报文
    tcp_traffic = []

    # 构造三次握手的SYN包
    syn_packet = ip_src_pack/TCP(sport=src_port, dport=dst_port, seq=seq_req, flags="S", window=64240,
                                 options=[("MSS", 1460), ("NOP", 1), ('WScale', 8), ("NOP", 1), ("NOP", 1), ("SAckOK", "")])
    # 构造三次握手的SYN/ACK包
    syn_ack_packet = ip_dst_pack/TCP(sport=dst_port, dport=src_port, flags="SA", seq=seq_rsp, ack=syn_packet[TCP].seq + 1,
                                     options=[("MSS", 1452), ("NOP", 1), ("NOP", 1), ("SAckOK", ""), ("NOP", 1), ('WScale', 7)])
    # 构造三次握手的ACK包
    ack_packet = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags="A", seq=syn_ack_packet[TCP].ack, ack=syn_ack_packet[TCP].seq + 1)
    three_handshake_list = [syn_packet, syn_ack_packet, ack_packet]

    # 先将三次握手报文放入全包中
    tcp_traffic += three_handshake_list

    # 遍历所有的req和rsp，创建包
    # 记录上一个请求/响应的长度，用于同步seq
    previous_req_content_len = 0
    previous_rsp_content_len = 0
    # 记录一下最后一个响应包的长度，用于构造挥手报文
    last_fragment_rsp_len = 0
    for i, (each_req, each_rsp) in enumerate(zip(req_content_list, rsp_content_list)):
        # 前置操作
        each_req = re.sub(r"[\s\r\n]", "", each_req)
        each_req = get_bytes_from_txt(each_req)
        # 构造TCP请求包和请求包的确认包
        tcp_req_packet_list, tcp_req_packet_ack_list = \
            get_tcp_req_packet(each_req, syn_ack_packet, ack_packet, ip_src_pack, ip_dst_pack, src_port, dst_port, add=previous_req_content_len, add2=previous_rsp_content_len)
        previous_req_content_len += len(each_req)

        # 构造TCP响应包
        each_rsp = re.sub(r"[\s\r\n]", "", each_rsp)
        each_rsp = get_bytes_from_txt(each_rsp)
        tcp_rsp_packet_list, tcp_rsp_packet_ack_list, last_fragment_rsp_len = \
            get_tcp_rsp_packet(each_rsp, tcp_req_packet_ack_list[-1], ip_src_pack, ip_dst_pack, src_port=dst_port, dst_port=src_port)
        previous_rsp_content_len += len(each_rsp)

        # 将所有的请求响应放到全包中
        tcp_traffic += tcp_req_packet_list
        tcp_traffic += tcp_req_packet_ack_list
        tcp_traffic += tcp_rsp_packet_list
        tcp_traffic += tcp_rsp_packet_ack_list

    # 构造挥手包，由服务端发起
    fin_packet = ip_dst_pack/TCP(sport=dst_port, dport=src_port, flags="FA", seq=tcp_rsp_packet_list[-1][TCP].seq + last_fragment_rsp_len, ack=tcp_rsp_packet_list[-1][TCP].ack)
    ack_packet_close = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags="A", seq=fin_packet[TCP].ack, ack=fin_packet[TCP].seq + 1)
    ack_packet_close2 = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags="FA", seq=ack_packet_close[TCP].seq, ack=fin_packet[TCP].seq + 1)
    fin_packet_ack = ip_dst_pack/TCP(sport=dst_port, dport=src_port, flags="A", seq=ack_packet_close2[TCP].ack, ack=ack_packet_close2[TCP].seq + 1)
    last_four_handshake_list = [fin_packet, ack_packet_close, ack_packet_close2, fin_packet_ack]

    tcp_traffic += last_four_handshake_list

    # 将流量报文保存到本地
    try:
        wrpcap(save_path, [tcp_traffic])
    except Exception as e:
        return {"success": False, "level": "error", "msg": f"异常详情：{e}"}
    time.sleep(1.5)
    return {"success": True, "level": "success", "msg": "报文生成成功！"}


def get_bytes_from_txt(tcp_all_payload):
    """
    此函数用于提取payload中的十六进制部分
    :param tcp_all_payload:
    :return:
    """
    # pcap_payload_hex_list = re.findall(r"(\x20[0-9a-f]{2})(?=\s)", tcp_all_payload)
    pcap_payload_hex_list = re.findall(r"([0-9a-fA-f]{2})", tcp_all_payload)
    bytes_string = b''
    for each_hex in pcap_payload_hex_list:
        bytes_string += bytes.fromhex(each_hex.strip())
    return bytes_string


def verify_tcp_req_rsp(ori_req_list: list, ori_rsp_list: list):
    # 判断tcp请求/响应部分payload的合规性
    # tcp部分全部使用原始数据判断
    for req, rsp in zip(ori_req_list, ori_rsp_list):
        req = re.sub(r"[\s\r\n]", "", req)
        rsp = re.sub(r"[\s\r\n]", "", rsp)
        # 判断请求内容是否合规
        if not bool(re.fullmatch(r"([0-9a-fA-F]{2})+", req)):
            return {"success": False, "msg": "请求内容异常，请修改请求内容"}
        if not bool(re.fullmatch(r"([0-9a-fA-F]{2})+", rsp)):
            return {"success": False, "msg": "响应内容异常，请修改响应内容"}

    return {"success": True}
