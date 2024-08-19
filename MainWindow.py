import sys

from PyQt5.QtWidgets import QMainWindow
from views.Main import Ui_MainWindow  # 导入对话框类

from controllers import OSController, PayloadController


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        # 实例化对话框类
        super(MainWindow, self).__init__()
        self.setupUi(self)

        """ 为了不破坏ui转换的py文件的内容，QT-Designer里找不到的一些设置，暂时在这里设置 """
        # 设置log展示框最大行数
        self.textBrowser_log.document().setMaximumBlockCount(256)
        # 用字典设置一些简单的全局配置
        self.settings = {}

        """ 为按钮绑定事件 """
        self.pushButton_select_dir.clicked.connect(self.slot_select_dir)
        self.pushButton_open_dir.clicked.connect(self.slot_open_dir)
        self.pushButton_add_default_req.clicked.connect(self.slot_add_default_req)
        self.pushButton_add_default_rsp.clicked.connect(self.slot_add_default_rsp)

    """ 定义槽函数 """
    # 选择文件夹
    def slot_select_dir(self):
        OSController.select_dir(self)

    # 打开文件夹
    def slot_open_dir(self):
        OSController.open_dir(self)

    # 添加默认请求payload
    def slot_add_default_req(self):
        PayloadController.add_default_req_rsp(self)

    # 添加默认响应payload
    def slot_add_default_rsp(self):
        PayloadController.add_default_req_rsp(self, "rsp")
