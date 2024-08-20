class TextLog:
    def __init__(self, main_window):
        self.textBrowser_log = main_window.textBrowser_log
        self.SEPARATOR = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++"

    def info_log(self, message, with_separator=False):
        self.textBrowser_log.append("[INFO] " + message)
        if with_separator:
            self.textBrowser_log.append(self.SEPARATOR)

    def error_log(self, message, with_separator=False):
        self.textBrowser_log.append('<font color="#ff0000">[ERROR] ' + message + '</font>')
        if with_separator:
            self.textBrowser_log.append(self.SEPARATOR)
