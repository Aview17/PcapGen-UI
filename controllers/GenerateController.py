from PyQt5.QtWidgets import QRadioButton


def gen_pcap(main_window):
    # 根据radioButton选中的索引获取需要生成的协议类型 HTTP/TCP/UDP
    selected_protocol = "HTTP"
    selected_radio = [radio for radio in main_window.verticalGroupBox.findChildren(QRadioButton) if radio.isChecked()].pop()
    if "TCP" in selected_radio.text():
        selected_protocol = "TCP"
    elif "UDP" in selected_radio.text():
        selected_protocol = "UDP"
    main_window.text_log.info_log(f"选择生成协议：{selected_protocol}")


