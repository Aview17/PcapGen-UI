from PyQt5.QtWidgets import QMessageBox

from models.default_communication_filled import default_req_dict, default_rsp_dict


def add_default_req_rsp(main_window, communicate_direction="req"):
    if communicate_direction == "req":
        # 获取下拉框中选择的默认 请求/响应 对应的payload
        default_payload = default_req_dict[main_window.comboBox_select_default_req.currentText()]
        # 在当前的tab页中的textEdit里填充选定的payload
        # 由于只有tabWidget只有一个控件所以直接取索引0
        now_text_edit_obj = main_window.tabWidget_3.currentWidget().children()[0]
    else:
        default_payload = default_rsp_dict[main_window.comboBox_select_default_rsp.currentText()]
        now_text_edit_obj = main_window.tabWidget_2.currentWidget().children()[0]

    if now_text_edit_obj.toPlainText().strip():
        communicate = {"req": "请求", "rsp": "响应"}
        dialog = QMessageBox.information(main_window, "提示", f"当前{communicate[communicate_direction]}页存在Payload信息，是否覆盖",
                                         QMessageBox.No | QMessageBox.Yes, QMessageBox.Yes)
        if dialog == QMessageBox.No:
            return

    now_text_edit_obj.setPlainText(default_payload)
