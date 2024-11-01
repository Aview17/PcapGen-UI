"""
    工具函数
"""
import re
import random


def determine_ipv4_format(ipv4_address: str):
    """
    用于判断ip是否符合格式
    :param ipv4_address: ipv4地址
    :return: Ture/False
    """
    return True if \
        re.search(r'(((2((5[0-5])|([0-4]\d)))|([0-1]?\d{1,2}))(\.((2((5[0-5])|([0-4]\d)))|([0-1]?\d{1,2}))){3})',
                  ipv4_address, re.IGNORECASE) \
        else False


def determine_port_format(port):
    """
    用于判断端口是否符合格式
    :param port: 端口
    :return: Ture/False
    """
    try:
        is_in_range = (0 < int(port) <= 65535)
    except Exception as e:
        return False

    return is_in_range


def generate_mac_address(separator=":", case="lower", mode="single", group=2):
    """
    用于生成MAC地址的函数
    :param separator: 分隔符，常见的有：-等
    :param case: 格式 lower-小写；upper-大写
    :param mode: 模式 single-单播；group-组播；broadcast-广播
    :param group: 分组，当group为2时返回形如ff-ff-ff-ff-ff-ff的地址，为4时返回形如ffff-ffff-ffff的地址
    :return: mac地址
    """
    if mode == "broadcast":
        if group == 2:
            broadcast_mac = separator.join(["ff"] * 6)
        else:
            broadcast_mac = separator.join(["ffff"] * 3)
        return broadcast_mac if case == "lower" else broadcast_mac.upper()

    first_byte = random.randint(0x00, 0xff)
    if mode == "single":
        # 单播，第一字节为偶数
        one = [first_byte if first_byte % 2 == 0 else first_byte - 0x01]
    else:
        # 组播，第一字节为奇数数
        one = [first_byte if first_byte % 2 == 1 else first_byte + 0x01]

    five = [random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    mac = one + five

    if group == 2:
        mac_str = separator.join(map(lambda x: "%02x" % x, mac))
    else:
        mac_str = separator.join(map(lambda x: "%04x" % x, mac))

    return mac_str if case == "lower" else mac_str.upper()


def generate_c_section_ip(src_ip="", dst_ip=""):
    """
    用于随机生成相同C段的源/目的地址
    :return: 源ip，目的ip
    """
    # 自定义源、目的ip的情况下不做任何操作返回
    if src_ip and dst_ip:
        return src_ip, dst_ip
    # 完全随机的情况下 生成随机源目的ip
    elif not src_ip and not dst_ip:
        # 生成随机C段目的地址
        three = random.randint(1, 254)
        four = random.randint(130, 254)
        dst_c_section = f"192.168.{str(three)}.{str(four)}"

        # 根据目的地址生成相同C段源地址
        src_four = random.randint(1, 129)
        dip_array = dst_c_section.split(".")
        dip_array[-1] = str(src_four)
        src_c_section = ".".join(dip_array)

        return src_c_section, dst_c_section
    # 目的ip随机的情况下，直接随机一个A段的公网地址
    elif src_ip and not dst_ip:
        ip_array = [str(random.randint(20, 100)), str(random.randint(1, 254)),
                    str(random.randint(1, 254)), str(random.randint(1, 254))]
        dst_ip = ".".join(ip_array)
        return src_ip, dst_ip
    # 源ip随机的情况下，根据目的地址生成相同C段源地址
    else:
        src_four = random.randint(1, 254)
        dip_array = dst_ip.split(".")
        # 避免随机到原目的ip相同的情况
        if dip_array[-1] == str(src_four):
            src_four = (src_four - 1) if src_four != 1 else (src_four + 1)
        dip_array[-1] = str(src_four)
        src_c_section = ".".join(dip_array)
        return src_c_section, dst_ip


def generate_s_d_prt(s_port=0, d_port=0):
    """
    用于随机生成源目的端口
    :param s_port:
    :param d_port:
    :return:
    """
    # 自定义源、目的端口的情况下不做任何操作返回
    if int(s_port) and int(d_port):
        return int(src_ip), int(dst_ip)
    # 完全随机的情况下 生成随机源目的端口
    elif not int(s_port) and not int(d_port):
        random_s_port = random.randint(30000, 65500)
        random_d_port = random.randint(1000, 20000)
        return random_s_port, random_d_port
    # 目的端口随机的情况
    elif int(s_port) and not int(d_port):
        random_d_port = random.randint(1000, 20000)
        return int(s_port), random_d_port
    # 源端口随机的情况
    else:
        random_s_port = random.randint(30000, 65500)
        return random_s_port, int(d_port)


if __name__ == "__main__":
    print(generate_c_section_ip("192.168.6.1", dst_ip="192.168.6.1"))
