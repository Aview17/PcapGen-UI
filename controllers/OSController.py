import os

from PyQt5 import QtWidgets


def select_dir(main_window):
    # 设置记录上次打开的目录
    last_path = main_window.settings.get("LastFilePath") if "LastFilePath" in main_window.settings.keys() else "C:/"
    selected_dir = QtWidgets.QFileDialog.getExistingDirectory(None, "选取文件夹", last_path)  # 起始路径
    main_window.settings["LastFilePath"] = selected_dir
    if selected_dir:
        main_window.lineEdit_output_path.setText(selected_dir)


def open_dir(main_window):
    folder = main_window.lineEdit_output_path.text()
    if folder is None or len(folder) < 1:
        main_window.text_log.error_log("未选择文件夹，无法打开", True)
    else:
        try:
            os.startfile(folder)
        except Exception as e:
            main_window.text_log.error_log(f"{str(e)}", True)
