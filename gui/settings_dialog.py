import os
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QLabel, QMessageBox, QTabWidget, QVBoxLayout, QWidget,
)

from .widgets import (
    AnimatedButton, AnimatedComboBox, ButtonOnlySpinBox,
)


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        self.lang = parent.lang if parent and hasattr(parent, "lang") else None
        super().__init__(parent)

        self.setWindowTitle(self.lang.t("settings.title") if self.lang else "Settings")
        self.setFixedWidth(400)

        self.parent_window = parent if hasattr(parent, "settings") else None
        self.settings = self.parent_window.settings

        main_layout = QVBoxLayout(self)

        tabs = QTabWidget()
        main_layout.addWidget(tabs)

        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)
        general_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        general_layout.setContentsMargins(10, 10, 10, 10)

        self.language_combo = AnimatedComboBox()
        lang_folder = self.lang.lang_dir
        for filename in os.listdir(lang_folder):
            if filename.endswith(".json"):
                lang_code = filename[:-5]
                display_name = self.lang.t(f"settings.language.{lang_code}")
                self.language_combo.addItem(display_name, lang_code)

        current_language = self.settings.value("language", "en")
        index = self.language_combo.findData(current_language)
        if index >= 0:
            self.language_combo.setCurrentIndex(index)

        general_layout.addWidget(QLabel(self.lang.t("settings.language")))
        general_layout.addWidget(self.language_combo)

        self.theme_combo = AnimatedComboBox()
        self.theme_combo.addItem(self.lang.t("settings.theme.light"), "light")
        self.theme_combo.addItem(self.lang.t("settings.theme.dark"), "dark")
        self.theme_combo.addItem(self.lang.t("settings.theme.system"), "system")

        current_theme = self.settings.value("theme", "light")
        use_system = self.settings.value("use_system_theme", False, type=bool)
        if use_system:
            self.theme_combo.setCurrentIndex(2)
        else:
            self.theme_combo.setCurrentIndex(0 if current_theme == "light" else 1)

        general_layout.addWidget(QLabel(self.lang.t("settings.theme")))
        general_layout.addWidget(self.theme_combo)

        tabs.addTab(general_tab, self.lang.t("settings.tab.general"))

        other_tab = QWidget()
        other_layout = QVBoxLayout(other_tab)
        other_layout.setAlignment(Qt.AlignmentFlag.AlignTop) 
        other_layout.setContentsMargins(10, 10, 10, 10)

        self.encryption_combo = AnimatedComboBox()
        self.encryption_combo.addItem(self.lang.t("settings.encryption.always_ask"), "always_ask")
        self.encryption_combo.addItem(self.lang.t("settings.encryption.auto_delete"), "auto_delete")
        self.encryption_combo.addItem(self.lang.t("settings.encryption.auto_secure_delete"), "auto_secure_delete")
        self.encryption_combo.addItem(self.lang.t("settings.encryption.never_delete"), "never_delete")

        current_encryption = self.settings.value("delete_file_after_encryption", "always_ask")
        index = self.encryption_combo.findData(current_encryption)
        if index >= 0:
            self.encryption_combo.setCurrentIndex(index)

        other_layout.addWidget(QLabel(self.lang.t("settings.encryption")))
        other_layout.addWidget(self.encryption_combo)

        self.decryption_combo = AnimatedComboBox()
        self.decryption_combo.addItem(self.lang.t("settings.decryption.always_ask"), "always_ask")
        self.decryption_combo.addItem(self.lang.t("settings.decryption.auto_delete"), "auto_delete")
        self.decryption_combo.addItem(self.lang.t("settings.decryption.never_delete"), "never_delete")

        current_decryption = self.settings.value("delete_file_after_decryption", "always_ask")
        index = self.decryption_combo.findData(current_decryption)
        if index >= 0:
            self.decryption_combo.setCurrentIndex(index)

        other_layout.addWidget(QLabel(self.lang.t("settings.decryption")))
        other_layout.addWidget(self.decryption_combo)

        self.overwrite_passes_spinbox = ButtonOnlySpinBox()
        self.overwrite_passes_spinbox.setRange(3, 10)
        self.overwrite_passes_spinbox.setValue(
            self.settings.value("secure_delete_passes", 3, type=int)
        )

        other_layout.addWidget(QLabel(self.lang.t("settings.overwrite.passes")))
        other_layout.addWidget(self.overwrite_passes_spinbox)

        tabs.addTab(other_tab, self.lang.t("settings.tab.other"))

        close_button = AnimatedButton(self.lang.t("settings.save.close"))
        close_button.clicked.connect(self.apply_and_close)
        main_layout.addWidget(close_button)

    def apply_and_close(self):
        theme_choice = self.theme_combo.currentData()
        if theme_choice == "system":
            self.settings.setValue("use_system_theme", True)
            self.parent_window.apply_system_theme()
        else:
            self.settings.setValue("use_system_theme", False)
            self.settings.setValue("theme", theme_choice)
            if theme_choice == "light":
                self.parent_window.apply_light_theme()
            else:
                self.parent_window.apply_dark_theme()

        new_lang = self.language_combo.currentData()
        current_lang = self.settings.value("language", "en")

        if new_lang != current_lang:
            msg_box = QMessageBox(self.parent_window)
            msg_box.setWindowTitle(self.lang.t("information"))
            msg_box.setText(self.lang.t("settings.restart"))
            now_button = msg_box.addButton(self.lang.t("now"), QMessageBox.AcceptRole)
            later_button = msg_box.addButton(self.lang.t("later"), QMessageBox.AcceptRole)
            cancel_button = msg_box.addButton(self.lang.t("operations.cancel"), QMessageBox.RejectRole)
            msg_box.setDefaultButton(now_button)
            msg_box.exec()

            clicked = msg_box.clickedButton()
            if clicked == now_button:
                self.settings.setValue("language", new_lang)
                python = sys.executable
                os.execl(python, python, *sys.argv)
            elif clicked == later_button:
                self.settings.setValue("language", new_lang)
            elif clicked == cancel_button:
                index = self.language_combo.findData(current_lang)
                if index >= 0:
                    self.language_combo.setCurrentIndex(index)
                pass
        else:
            self.close()

        self.settings.setValue("delete_file_after_encryption", self.encryption_combo.currentData())
        self.settings.setValue("delete_file_after_decryption", self.decryption_combo.currentData())
        self.settings.setValue("secure_delete_passes", self.overwrite_passes_spinbox.value())