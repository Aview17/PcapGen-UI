"""
    此程序内部使用工具函数，区别于通用类型的工具函数
"""
import random
from datetime import datetime


def adjustment_packet_timestamp(all_packet):
    """
    用于调整生成报文的时间戳，让其更真实
    :param all_packet:
    :return:
    """
    base_time = datetime.now().timestamp()
    previous_pkt_time = base_time
    for i, pkt in enumerate(all_packet):
        this_pkt_time = previous_pkt_time + random.uniform(0.001, 0.003)  # 每个包间隔随机秒数
        pkt.time = this_pkt_time
        previous_pkt_time = this_pkt_time

    return all_packet
