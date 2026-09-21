import os
import sys

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from gui import MainWindow


if __name__ == "__main__":
    app = QApplication(sys.argv)

    if getattr(sys, "frozen", False):
        application_path = sys._MEIPASS
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))

    icon_path = os.path.join(
        application_path,
        "assets",
        "icon.ico",
    )

    window = MainWindow()
    window.setWindowIcon(QIcon(icon_path))
    window.show()

    sys.exit(app.exec())