"""
    工具函数
"""
import random


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


if __name__ == "__main__":
    print(generate_mac_address())
    print(generate_mac_address(mode="group"))
