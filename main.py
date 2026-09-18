import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from GUI import MainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)
    if getattr(sys, 'frozen', False):
        application_path = sys._MEIPASS
    elif __file__:
        application_path = os.path.dirname(__file__)
    icon_path = os.path.join(application_path, "assets", "icon.ico")
    window = MainWindow()
    window.setWindowIcon(QIcon(icon_path))
    window.show()
    sys.exit(app.exec())