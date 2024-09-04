import os

from PyQt5.QtWidgets import QRadioButton, QTextEdit

from logic.HTTPPcapGenLogic import create_http_pcap
from logic.TCPPcapGenLogic import create_tcp_pcap
from logic.UDPPcapGenLogic import create_udp_pcap

func_dict = {"HTTP": create_http_pcap, "TCP": create_tcp_pcap, "UDP": create_udp_pcap}


def gen_pcap(main_window):
    # 根据radioButton选中的索引获取需要生成的协议类型 HTTP/TCP/UDP
    selected_protocol = "HTTP"
    selected_radio = [radio for radio in main_window.verticalGroupBox.findChildren(QRadioButton) if radio.isChecked()].pop()
    if "TCP" in selected_radio.text():
        selected_protocol = "TCP"
    elif "UDP" in selected_radio.text():
        selected_protocol = "UDP"
    main_window.text_log.info_log(f"选择生成协议：{selected_protocol}")

    req_list, rsp_list, is_len_equal = _get_req_rsp_list(main_window)
    if not is_len_equal:
        main_window.text_log.error_log("请求个数应与响应个数相同！（可选择默认请求/响应进行填充）")
        return

    # 获取保存路径
    save_path = _get_save_path(main_window)
    if len(save_path) == 0:
        main_window.text_log.error_log("文件路径选择有误或是路径下已存在同名文件", True)
        return

    # 创建报文
    main_window.text_log.info_log("正在生成报文，请稍等...")
    res = func_dict[selected_protocol](req_list, rsp_list, save_path)

    # 创建失败直接return
    if not res["success"]:
        if res["level"] == "error":
            main_window.text_log.error_log(res["msg"], True)
        if res["level"] == "warning":
            main_window.text_log.warning_log(res["msg"])
        return
    # 创建成功则输出成功
    if res["success"]:
        if res["level"] == "success":
            main_window.text_log.success_log(res["msg"], True)
        if res["level"] == "info":
            main_window.text_log.info_log(res["msg"])


def _get_req_rsp_list(main_window):
    # 获取tabWidget的text区域中所有的请求内容
    all_req_q_text = main_window.tabWidget_3.findChildren(QTextEdit)
    req_list = []
    for each_q_text in all_req_q_text:
        if each_q_text.toPlainText():
            req_list.append(each_q_text.toPlainText())
    # 获取tabWidget的text区域中所有的响应内容
    all_rsp_q_text = main_window.tabWidget_2.findChildren(QTextEdit)
    rsp_list = []
    for each_q_text in all_rsp_q_text:
        if each_q_text.toPlainText():
            rsp_list.append(each_q_text.toPlainText())

    return req_list, rsp_list, len(req_list) == len(rsp_list)


def _get_save_path(main_window):
    # 从文件夹与保存路径区域获取保存路径
    folder = main_window.lineEdit_output_path.text()
    filename = main_window.lineEdit_output_filename.text()
    full_path = folder + "/" + (filename if filename.endswith(".pcap") else filename + ".pcap")
    # 确认输出路径是否正常
    if folder is None or len(folder) < 1 or os.path.exists(full_path):
        return ""
    return full_path
