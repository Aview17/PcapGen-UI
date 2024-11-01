"""
    HTTP报文生成主逻辑
"""
import re

from scapy.all import *
from scapy.utils import wrpcap
from scapy.layers.inet import IP, TCP, Ether

from Tools import NetworkTools


def fix_content_length(request_body):
    content_length = re.search(r'Content-Length: (\d+)', request_body)
    request_body = re.sub(r"(?<!\r)\n", "\r\n", request_body)
    request_body = request_body.replace('\r\r', '\r')
    if content_length or (content_length is None and request_body[0:3] == 'GET'):
        if request_body[0:3] == 'GET':
            request_body = re.sub(r'Content-Length: \d+', 'Content-Length: 0', request_body)
            request_body = request_body.strip() + "\r\n\r\n"
            return request_body

        expected_length = int(content_length.group(1))

        try:
            body = request_body.split('\r\n\r\n', 1)[1]
            actual_length = len(body)
        except Exception as e:
            actual_length = 0

        if actual_length != expected_length:
            request_body = re.sub(r'Content-Length: \d+', f'Content-Length: {actual_length}', request_body)

    # POST请求必须要带Content-Length，不然会识别不到请求内容
    if content_length is None and request_body[0:4] == 'POST':
        try:
            # 需要取 除头部以外的所有内容，因为有些表单上传的位置也会出现\r\n\r\n，所以split限制只切1次
            body = request_body.split('\r\n\r\n', 1)[1]
            actual_length = len(body)
        except Exception as e:
            actual_length = 0

        request_body = request_body.replace("\r\n\r\n", f"\r\nContent-Length: {str(actual_length)}\r\n\r\n", 1)

    return request_body


def get_http_req_packet(all_http_request, syn_ack_packet, ack_packet, ip_src_pack, ip_dst_pack, src_port, dst_port, mtu=1460, add=0):
    if len(all_http_request) < mtu + 1:
        http_req_one = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags=24, seq=ack_packet[TCP].seq + add,
                                       ack=syn_ack_packet[TCP].seq + 1)/all_http_request.encode()
        http_req_ack_one = ip_dst_pack/TCP(sport=dst_port, dport=src_port, seq=http_req_one[TCP].ack,
                                           ack=http_req_one[TCP].seq + len(all_http_request.encode()), flags='A')
        return [http_req_one], [http_req_ack_one]

    # 处理超过MTU的报文
    http_req_packet_list = []
    http_req_packet_ack_list = []
    group_num = math.ceil(len(all_http_request) / int(mtu))
    for i in range(group_num):
        fragment_req = all_http_request.encode()[i*mtu: i*mtu+mtu]
        if i == 0:
            fragment_req_pack = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags="A", seq=ack_packet[TCP].seq,
                                                ack=syn_ack_packet[TCP].seq + 1)/fragment_req
        else:
            fragment_req_pack = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags=24, seq=ack_packet[TCP].seq + i * mtu,
                                                ack=syn_ack_packet[TCP].seq + 1)/fragment_req
        # 每个请求包的ack包
        fragment_req_ack_pack = ip_dst_pack/TCP(sport=dst_port, dport=src_port, seq=fragment_req_pack[TCP].ack,
                                                ack=fragment_req_pack[TCP].seq + len(fragment_req), flags='A')
        http_req_packet_list.append(fragment_req_pack)
        http_req_packet_ack_list.append(fragment_req_ack_pack)

    return http_req_packet_list, http_req_packet_ack_list


def get_http_rsp_packet(all_http_response, last_check_ack_pack, ip_dst_pack, src_port, dst_port, mtu=1460, add=0):
    if len(all_http_response) < mtu + 1:
        return [ip_dst_pack/TCP(sport=src_port, dport=dst_port, flags=24, seq=last_check_ack_pack[TCP].seq + add,
                                ack=last_check_ack_pack[TCP].ack)/all_http_response.encode()], \
               len(all_http_response.encode())
    # 处理超过mtu的响应体
    http_rsp_packet_list = []
    group_num = math.ceil(len(all_http_response) / int(mtu))
    last_fragment_rsp_len = 0   # 最后一段响应体的长度
    for i in range(group_num):
        fragment_rsp = all_http_response.encode()[i*mtu: i*mtu+mtu]
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

        http_rsp_packet_list.append(fragment_rsp_pack)

    return http_rsp_packet_list, last_fragment_rsp_len


def verify_req_rsp(ori_req_list: list, ori_rsp_list: list):
    # 判断请求部分payload的合规性
    for req in ori_req_list:
        # 判断请求方法是否正常
        if req[0: req.find("\x20")] not in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE',
                                            'PATCH', 'MOVE', 'COPY', 'LINK', 'UNLINK', 'WRAPPED']:
            return {"success": False, "msg": "请求方法异常，请修改请求方法"}
        # 判断Host字段是否正常
        if re.search(r"Host: (\d+\.){3}\d+(:\d+)?", req) is None and re.search(r"Host: (\w+\.)+\w+(:\d+)?", req) is None:
            return {"success": False, "msg": "Host字段异常，请修改Host字段（请使用ip/ip:port/domain/domain:port）"}

        # TODO 判断响应字段的合规性（暂时不加）

    return {"success": True}


def get_quadruple(request: str):
    # 从构造的请求体中获取Host的ip
    try:
        package_dip = re.search(r'Host: (((2((5[0-5])|([0-4]\d)))|([0-1]?\d{1,2}))(\.((2((5[0-5])|([0-4]\d)))|([0-1]?\d{1,2}))){3})', request, re.IGNORECASE).group(1)
    except AttributeError as attr_err:
        # 对于匹配不到Host中的ip的情况（头部缺失或直接为域名）设置默认ip
        package_dip = "192.168.3.25"

    # 同步源IP，掩码为24
    dip_array = package_dip.split(".")
    dip_array[-1] = "7" if dip_array[-1] != "7" else "8"
    package_sip = ".".join(dip_array)

    # 从构造的请求体中获取Host的端口
    try:
        package_dport = re.search(r'Host:.*?:(\d+)', request, re.IGNORECASE).group(1)
        package_dport = int(package_dport)
    except AttributeError as attr_err:
        # 对于匹配不到Host中的port的情况（头部缺失或为80）设置默认端口为80
        package_dport = 80
    # 源端口随机产生
    package_sport = random.randint(48000, 65535)

    return package_sip, package_sport, package_dip, package_dport


def create_http_pcap(req_content_list, rsp_content_list, save_path, placeholder):
    # 先判断一下请求/响应是否合规
    verify_res = verify_req_rsp(req_content_list, rsp_content_list)
    if not verify_res["success"]:
        verify_res["level"] = "error"
        return verify_res

    # 获取四元组（只用第一个请求）
    src_ip, src_port, dst_ip, dst_port = get_quadruple(req_content_list[0])

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
    http_traffic = []

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
    http_traffic += three_handshake_list

    # 遍历所有的req和rsp，创建包
    # 记录上一个请求/响应的长度，用于同步seq
    previous_req_content_len = 0
    previous_rsp_content_len = 0
    # 记录一下最后一个响应包的长度，用于构造挥手报文
    last_fragment_rsp_len = 0
    for i, (each_req, each_rsp) in enumerate(zip(req_content_list, rsp_content_list)):
        # 前置操作
        each_req = fix_content_length(each_req)
        # 构造HTTP请求包和请求包的确认包
        http_req_packet_list, http_req_packet_ack_list = \
            get_http_req_packet(each_req, syn_ack_packet, ack_packet, ip_src_pack, ip_dst_pack, src_port, dst_port, add=previous_req_content_len)
        previous_req_content_len += len(each_req.encode())

        # 构造HTTP响应包
        # 带有标签的响应体需要保证最后要有一个\x0a，不然wireshark会无法识别HTTP（不知道为什么）
        if each_rsp.endswith(">"):
            each_rsp = each_rsp.strip() + "\n"
        each_rsp = fix_content_length(each_rsp)
        http_rsp_packet_list, last_fragment_rsp_len = \
            get_http_rsp_packet(each_rsp, http_req_packet_ack_list[-1], ip_dst_pack, src_port=dst_port, dst_port=src_port, add=previous_rsp_content_len)
        previous_rsp_content_len += len(each_rsp.encode())

        # 将所有的请求响应放到全包中
        http_traffic += http_req_packet_list
        http_traffic += http_req_packet_ack_list
        http_traffic += http_rsp_packet_list

    # 构造挥手包，由服务端发起
    fin_packet = ip_dst_pack/TCP(sport=dst_port, dport=src_port, flags="FA", seq=http_traffic[-1][TCP].seq + last_fragment_rsp_len, ack=http_traffic[-1][TCP].ack)
    ack_packet_close = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags="A", seq=fin_packet[TCP].ack, ack=fin_packet[TCP].seq + 1)
    ack_packet_close2 = ip_src_pack/TCP(sport=src_port, dport=dst_port, flags="FA", seq=ack_packet_close[TCP].seq, ack=fin_packet[TCP].seq + 1)
    fin_packet_ack = ip_dst_pack/TCP(sport=dst_port, dport=src_port, flags="A", seq=ack_packet_close2[TCP].ack, ack=ack_packet_close2[TCP].seq + 1)
    last_four_handshake_list = [fin_packet, ack_packet_close, ack_packet_close2, fin_packet_ack]

    http_traffic += last_four_handshake_list

    # 将流量报文保存到本地
    try:
        wrpcap(save_path, [http_traffic])
    except Exception as e:
        return {"success": False, "level": "error", "msg": f"异常详情：{e}"}
    time.sleep(1.5)
    return {"success": True, "level": "success", "msg": "报文生成成功！"}
