import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import os
import sys
import json
import re
from time import time
from psutil import Process
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFileDialog, QComboBox, QProgressBar,
    QGroupBox, QDialog, QSizePolicy, QMessageBox, QMenu, QWidgetAction, QTabWidget, QSpinBox
)
from PySide6.QtCore import Qt, QSettings, QTimer, Signal, QLocale
from PyTaskbar import ProgressType, TaskbarProgress
import darkdetect
from Algorithms import ALGORITHMS, CryptoWorker, generate_key

class MainWindow(QMainWindow):
    settings = QSettings("Vyroxes", "File Encryption and Decryption")

    def __init__(self):
        super().__init__()

        self._initialize_default_settings()

        self.lang = LanguageManager(self.settings)

        self.setWindowTitle(self.lang.t("app.title"))
        self.setMinimumSize(600, 578)
        self.resize(600, 578)

        self._process = Process(os.getpid())
        self._memory_samples = []
        self._crypto_start_time = None
        self._memory_timer = QTimer()
        self._memory_timer.timeout.connect(self._sample_memory)

        if sys.platform == "win32":
            hwnd = int(self.winId())
            self.taskbar_progress = TaskbarProgress(hwnd)
            self.taskbar_progress.set_progress_type(ProgressType.NORMAL)
            self.taskbar_progress.set_progress(0)

        central_widget = QWidget()
        general_layout = QVBoxLayout(central_widget)

        header_layout = QHBoxLayout()
        header_layout.addStretch()

        self.settings_button = QPushButton(self.lang.t("settings.title"))
        self.settings_button.setObjectName("settingsButton")
        self.settings_button.clicked.connect(self.open_settings)

        header_layout.addWidget(self.settings_button)
        general_layout.addLayout(header_layout)

        general_layout.addWidget(self.create_file_section())
        general_layout.addWidget(self.create_key_section())
        general_layout.addWidget(self.create_algorithm_section())
        general_layout.addWidget(self.create_operations_section())

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        general_layout.addWidget(self.progress_bar)

        self.setCentralWidget(central_widget)
        self.load_theme_on_start()
        self.load_history_on_start()
        self.current_system_theme = None

        self.theme_timer = QTimer(self)
        self.theme_timer.timeout.connect(self.check_system_theme)
        self.theme_timer.start(1000)

    def _initialize_default_settings(self):
        preferred_languages = [
            lang.split("-")[0].lower()
            for lang in QLocale.system().uiLanguages()
        ]

        system_lang = next(
            (
                lang for lang in preferred_languages
                if os.path.exists(os.path.join("lang", f"{lang}.json"))
            ),
            "en"
        )

        defaults = {
            "language": system_lang,
            "theme": "light",
            "use_system_theme": True,
            "delete_file_after_encryption": "always_ask",
            "delete_file_after_decryption": "always_ask",
            "secure_delete_passes": 3,
            "history_limit": 10,
        }

        for key, value in defaults.items():
            if self.settings.value(key) is None:
                self.settings.setValue(key, value)

    def _sample_memory(self):
        if hasattr(self, "_process"):
            self._memory_samples.append(self._process.memory_info().rss)

    def create_select_row(self, text, select_callback, clear_callback, history_callback=None):
        layout = QHBoxLayout()

        history_button = QPushButton("☰")
        history_button.setFixedSize(28, 28)
        history_button.setObjectName("historyButton")

        if history_callback:
            history_button.clicked.connect(
                lambda: history_callback(history_button)
            )

        select_button = QPushButton(text)

        clear_button = QPushButton("×")
        clear_button.setObjectName("clearButton")
        clear_button.setFixedSize(28, 28)
        clear_button.setEnabled(False)

        select_button.clicked.connect(select_callback)
        clear_button.clicked.connect(clear_callback)

        layout.addWidget(history_button, 1)
        layout.addWidget(select_button, 8)
        layout.addWidget(clear_button, 1)

        return layout, clear_button

    def create_file_section(self):
        group = QGroupBox(self.lang.t("file.group"))
        layout = QVBoxLayout(group)

        row_layout, self.clear_file_button = self.create_select_row(
            self.lang.t("file.select"),
            self.select_file,
            self.clear_file,
            lambda btn: self.show_history_menu(self.file_label, "file", btn)
        )

        self.file_label = ClickablePathLabel("file", clear_button=self.clear_file_button, parent=self)
        self.file_label.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred
        )
        self.file_label.pathChanged.connect(self.update_operation_buttons_state)
        self.file_label.pathChanged.connect(self.on_file_path_changed)

        layout.addWidget(self.file_label)
        layout.addLayout(row_layout)

        return group

    def create_key_section(self):
        self.key_group = QGroupBox(self.lang.t("key.group"))
        self.key_layout = QVBoxLayout(self.key_group)

        self.single_key_widget = self.create_single_key()
        self.rsa_keys_widget = self.create_rsa_keys()

        self.key_layout.addWidget(self.single_key_widget)
        self.key_layout.addWidget(self.rsa_keys_widget)

        self.rsa_keys_widget.hide()

        return self.key_group

    def create_single_key(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        row_layout, self.clear_key_button = self.create_select_row(
            self.lang.t("key.select"),
            self.select_key,
            self.clear_key,
            lambda btn: self.show_history_menu(self.key_label, "key", btn)
        )

        self.key_label = ClickablePathLabel("key", clear_button=self.clear_key_button, parent=self)
        self.key_label.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred
        )
        self.key_label.pathChanged.connect(self.update_operation_buttons_state)

        layout.addWidget(self.key_label)
        layout.addLayout(row_layout)

        self.generate_key_button = QPushButton(self.lang.t("key.generate"))
        self.generate_key_button.clicked.connect(lambda: self.generate_key("symmetric", False))

        layout.addWidget(self.generate_key_button)

        return widget

    def create_rsa_keys(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        row_layout, self.clear_private_key_button = self.create_select_row(
            self.lang.t("key.select.private"),
            self.select_private_key,
            self.clear_private_key,
            lambda btn: self.show_history_menu(self.private_key_label, "private_key", btn)
        )

        self.private_key_label = ClickablePathLabel("private_key", clear_button=self.clear_private_key_button, parent=self)
        self.private_key_label.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred
        )
        self.private_key_label.pathChanged.connect(self.update_operation_buttons_state)


        private_layout = QVBoxLayout()
        private_layout.addWidget(self.private_key_label)
        private_layout.addLayout(row_layout)

        row_layout, self.clear_public_key_button = self.create_select_row(
            self.lang.t("key.select.public"),
            self.select_public_key,
            self.clear_public_key,
            lambda btn: self.show_history_menu(self.public_key_label, "public_key", btn)
        )

        self.public_key_label = ClickablePathLabel("public_key", clear_button=self.clear_public_key_button, parent=self)
        self.public_key_label.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred
        )
        self.public_key_label.pathChanged.connect(self.update_operation_buttons_state)

        public_layout = QVBoxLayout()
        public_layout.addWidget(self.public_key_label)
        public_layout.addLayout(row_layout)
        
        self.generate_private_key_button = QPushButton(self.lang.t("key.generate.private"))
        self.generate_private_key_button.clicked.connect(lambda: self.generate_key("asymmetric", False))
        
        self.generate_public_key_button = QPushButton(self.lang.t("key.generate.public"))
        self.generate_public_key_button.clicked.connect(lambda: self.generate_key("asymmetric", True))
        
        private_layout.addWidget(self.generate_private_key_button)
        public_layout.addWidget(self.generate_public_key_button)

        layout.addLayout(private_layout)
        layout.addLayout(public_layout)

        return widget

    def create_algorithm_section(self):
        self.algorithm_group = QGroupBox(self.lang.t("algorithm.group"))
        self.algorithm_group.setFixedHeight(124)
        layout = QVBoxLayout(self.algorithm_group)

        top_row_layout = QHBoxLayout()
        top_row_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(list(ALGORITHMS.keys()))
        self.algorithm_combo.currentTextChanged.connect(self.update_algorithm_params)

        self.algorithm_info_button = QPushButton("?")
        self.algorithm_info_button.setFixedSize(28, 28)
        self.algorithm_info_button.setObjectName("infoButton")
        # self.algorithm_info_button.clicked.connect(self.show_algorithm_info)

        self.toggle_params_button = QPushButton(self.lang.t("algorithm.show.settings"))
        self.toggle_params_button.setCheckable(True)
        self.toggle_params_button.toggled.connect(self.toggle_algorithm_params)

        top_row_layout.addWidget(self.algorithm_combo)
        top_row_layout.addWidget(self.algorithm_info_button)
        top_row_layout.addWidget(self.toggle_params_button)

        self.algorithm_params_panel = QWidget()
        self.algorithm_params_panel.setVisible(False)
        self.algorithm_params_panel.setLayout(QHBoxLayout())

        layout.addLayout(top_row_layout)
        layout.addWidget(self.algorithm_params_panel)

        self.update_algorithm_params(self.algorithm_combo.currentText())

        return self.algorithm_group

    def create_operations_section(self):
        group = QGroupBox(self.lang.t("operations.group"))
        layout = QVBoxLayout(group)

        buttons_layout = QHBoxLayout()

        self.encrypt_sign_button = QPushButton(self.lang.t("operations.encrypt"))
        self.encrypt_sign_button.clicked.connect(self.start_encrypt_sign)
        self.encrypt_sign_button.setEnabled(False)
        self.decrypt_verify_button = QPushButton(self.lang.t("operations.decrypt"))
        self.decrypt_verify_button.clicked.connect(self.start_decrypt_verify)
        self.decrypt_verify_button.setEnabled(False)

        buttons_layout.addWidget(self.encrypt_sign_button)
        buttons_layout.addWidget(self.decrypt_verify_button)

        self.cancel_button = QPushButton(self.lang.t("operations.cancel"))
        self.cancel_button.clicked.connect(self.cancel_operation)
        self.cancel_button.setObjectName("cancelButton")
        self.cancel_button.setEnabled(False)

        layout.addLayout(buttons_layout)
        layout.addWidget(self.cancel_button)

        return group

    def update_clear_button(self, label, clear_button, empty_text):
        clear_button.setEnabled(label.text() != empty_text)

    def update_algorithm_params(self, algorithm_name):
        algorithm = ALGORITHMS.get(algorithm_name)
        if not algorithm:
            return

        if algorithm["type"] == "asymmetric":
            self.key_group.setTitle(self.lang.t("keys.group"))
            self.single_key_widget.hide()
            self.rsa_keys_widget.show()
        else:
            self.key_group.setTitle(self.lang.t("key.group"))
            self.rsa_keys_widget.hide()
            self.single_key_widget.show()

        layout = self.algorithm_params_panel.layout()
        layout.setContentsMargins(0, 0, 0, 0)
        self.clear_layout(layout)

        left_column = QVBoxLayout()
        middle_column = QVBoxLayout()
        right_column = QVBoxLayout()

        if algorithm["type"] == "symmetric":
            key_lengths = algorithm.get("key_lengths", [])
            modes = algorithm.get("modes", [])

            if key_lengths:
                key_lengths_label = QLabel(self.lang.t("algorithm.key.length"))
                self.key_lengths_combo = QComboBox()
                self.key_lengths_combo.addItems([str(k) for k in key_lengths])
                if len(key_lengths) == 1:
                    self.key_lengths_combo.setEnabled(False)
                left_column.addWidget(key_lengths_label)
                left_column.addWidget(self.key_lengths_combo)

            if modes:
                mode_label = QLabel(self.lang.t("algorithm.mode"))
                self.mode_combo = QComboBox()
                self.mode_combo.addItems(modes)
                if len(modes) == 1:
                    self.mode_combo.setEnabled(False)
                right_column.addWidget(mode_label)
                right_column.addWidget(self.mode_combo)

            if algorithm_name == "ASCON":
                self.key_lengths_combo.setEnabled(False)

                def sync_ascon_key_length(index):
                    if 0 <= index < self.key_lengths_combo.count():
                        self.key_lengths_combo.setCurrentIndex(index)

                sync_ascon_key_length(self.mode_combo.currentIndex())
                self.mode_combo.currentIndexChanged.connect(sync_ascon_key_length)
        
        elif algorithm["type"] == "asymmetric":
            key_lengths = algorithm.get("key_lengths", [])
            hashes = algorithm.get("hashes", [])
            paddings = algorithm.get("paddings", [])
            curves = algorithm.get("curves", [])

            if curves:
                curves_label = QLabel(self.lang.t("algorithm.curves"))
                self.curves_combo = QComboBox()
                self.curves_combo.addItems(curves)
                if len(curves) == 1:
                    self.curves_combo.setEnabled(False)
                left_column.addWidget(curves_label)
                left_column.addWidget(self.curves_combo)

            if key_lengths:
                key_lengths_label = QLabel(self.lang.t("algorithm.key.length"))
                self.key_lengths_combo = QComboBox()
                self.key_lengths_combo.addItems([str(k) for k in key_lengths])
                if len(key_lengths) == 1:
                    self.key_lengths_combo.setEnabled(False)
                left_column.addWidget(key_lengths_label)
                left_column.addWidget(self.key_lengths_combo)

            if paddings:
                paddings_label = QLabel(self.lang.t("algorithm.padding"))
                self.paddings_combo = QComboBox()
                self.paddings_combo.addItems(paddings)
                if len(paddings) == 1:
                    self.paddings_combo.setEnabled(False)
                middle_column.addWidget(paddings_label)
                middle_column.addWidget(self.paddings_combo)

            if hashes:
                hashes_label = QLabel(self.lang.t("algorithm.hashes"))
                self.hashes_combo = QComboBox()
                self.hashes_combo.addItems(hashes)
                if len(hashes) == 1:
                    self.hashes_combo.setEnabled(False)
                right_column.addWidget(hashes_label)
                right_column.addWidget(self.hashes_combo)

        self.update_operation_buttons_state()

        layout.addLayout(left_column)
        layout.addLayout(middle_column)
        layout.addLayout(right_column)

    def toggle_algorithm_params(self, state):
        self.algorithm_params_panel.setVisible(state)
        self.toggle_params_button.setText(
            self.lang.t("algorithm.hide.settings") if state else self.lang.t("algorithm.show.settings")
        )

    def clear_layout(self, layout):
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                child_layout = item.layout()
                if widget:
                    widget.setParent(None)
                elif child_layout:
                    self.clear_layout(child_layout)

    def update_operation_buttons_state(self):
        if not hasattr(self, "encrypt_sign_button") or not hasattr(self, "decrypt_verify_button"):
            return

        algorithm = ALGORITHMS.get(self.algorithm_combo.currentText())
        if not algorithm:
            self.encrypt_sign_button.setEnabled(False)
            self.decrypt_verify_button.setEnabled(False)
            return

        file_path = self.file_label.path
        is_file_selected = bool(file_path)
        is_enc_file = is_file_selected and file_path.lower().endswith(".enc")

        if algorithm["type"] == "asymmetric":
            has_keys = bool(self.private_key_label.path and self.public_key_label.path)
        else:
            has_keys = bool(self.key_label.path)

        self.encrypt_sign_button.setEnabled(is_file_selected and has_keys and not is_enc_file)
        self.decrypt_verify_button.setEnabled(is_file_selected and has_keys and is_enc_file)

        if self.algorithm_combo.currentText() in ("EdDSA", "ECDSA"):
            self.encrypt_sign_button.setText(self.lang.t("operations.sign"))
            self.decrypt_verify_button.setText(self.lang.t("operations.verify"))
        else:
            self.encrypt_sign_button.setText(self.lang.t("operations.encrypt"))
            self.decrypt_verify_button.setText(self.lang.t("operations.decrypt"))

    def open_settings(self):
        dialog = SettingsDialog(self)
        dialog.exec()

    def sizeof_fmt(self, num, suffix="B"):
        for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi"):
            if abs(num) < 1024.0:
                return f"{num:.1f} {unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f} Yi{suffix}"

    def _safe_file_size_fmt(self, path: str) -> str:
        try:
            return self.sizeof_fmt(os.path.getsize(path))
        except OSError:
            return "—"

    def load_metadata_from_enc(self, file_path: str) -> dict:
        try:
            with open(file_path, "rb") as f:
                head = f.read(1024)
            head_str = head.decode("utf-8", errors="ignore")

            match = re.search(r"\{.*?\}", head_str)
            if match:
                meta_json = match.group(0) + "}"
                meta = json.loads(meta_json)
                return meta, meta.get("params", {})
        except Exception as e:
            QMessageBox.warning(self, self.lang.t("warning"), self.lang.t("file.error.8") + str(e))
        return {}, {}

    def on_file_path_changed(self):
        path = self.file_label.path
        if path and path.lower().endswith(".enc"):
            meta, params = self.load_metadata_from_enc(path)

            algorithm = meta.get("algorithm")
            if algorithm and algorithm in ALGORITHMS:
                idx = self.algorithm_combo.findText(algorithm)
                if idx >= 0:
                    self.algorithm_combo.setCurrentIndex(idx)

            if hasattr(self, "mode_combo") and params.get("mode"):
                idx = self.mode_combo.findText(params["mode"])
                if idx >= 0:
                    self.mode_combo.setCurrentIndex(idx)

            if hasattr(self, "key_lengths_combo") and params.get("key_length"):
                idx = self.key_lengths_combo.findText(str(params["key_length"]))
                if idx >= 0:
                    self.key_lengths_combo.setCurrentIndex(idx)

            if hasattr(self, "hashes_combo") and params.get("hash"):
                idx = self.hashes_combo.findText(params["hash"])
                if idx >= 0:
                    self.hashes_combo.setCurrentIndex(idx)

            if hasattr(self, "paddings_combo") and params.get("padding"):
                idx = self.paddings_combo.findText(params["padding"])
                if idx >= 0:
                    self.paddings_combo.setCurrentIndex(idx)

            if hasattr(self, "curves_combo") and params.get("curve"):
                idx = self.curves_combo.findText(params["curve"])
                if idx >= 0:
                    self.curves_combo.setCurrentIndex(idx)

    def select_file(self):
        options = QFileDialog.Option()
        path, _ = QFileDialog.getOpenFileName(self, self.lang.t("file.select"), "", "All Files (*);;Encrypted Files (*.enc)", options=options)
        if path:
            self.file_label.setPath(path)
            self.history.add(path, "file")

    def clear_file(self):
        self.file_label.clearPath()

    def select_key(self):
        options = QFileDialog.Option()
        path, _ = QFileDialog.getOpenFileName(self, self.lang.t("key.select"), "", "Key Files (*.key);;All Files (*)", options=options)
        if path:
            self.key_label.setPath(path)
            self.history.add(path, "key")

    def clear_key(self):
        self.key_label.clearPath()

    def select_private_key(self):
        options = QFileDialog.Option()
        path, _ = QFileDialog.getOpenFileName(self, self.lang.t("key.select.private"), "", "Key Files (*.key);;All Files (*)", options=options)
        if path:
            self.private_key_label.setPath(path)
            self.history.add(path, "private_key")
    def clear_private_key(self):
        self.private_key_label.clearPath()

    def select_public_key(self):
        options = QFileDialog.Option()
        path, _ = QFileDialog.getOpenFileName(self, self.lang.t("key.select.public"), "", "Key Files (*.key);;All Files (*)", options=options)
        if path:
            self.public_key_label.setPath(path)
            self.history.add(path, "public_key")

    def clear_public_key(self):
        self.public_key_label.clearPath()

    def generate_key(self, key_type="symmetric", public=False):
        options = QFileDialog.Option()

        if key_type == "symmetric" and public:
            return
        
        if key_type == "asymmetric" and public and not self.private_key_label.path:
            QMessageBox.warning(self, self.lang.t("warning"), self.lang.t("key.error.2"))
            return

        if key_type == "asymmetric" and not public:
            key_path, _ = QFileDialog.getSaveFileName(self, self.lang.t("key.save.private"), self.lang.t("key.private.file"), "Key Files (*.key);;All Files (*)", options=options)
        elif key_type == "asymmetric" and public:
            key_path, _ = QFileDialog.getSaveFileName(self, self.lang.t("key.save.public"), self.lang.t("key.public.file"), "Key Files (*.key);;All Files (*)", options=options)
        else:
            key_path, _ = QFileDialog.getSaveFileName(self, self.lang.t("key.save"), self.lang.t("key.file"), "Key Files (*.key);;All Files (*)", options=options)
        if not key_path:
            return
        
        try:
            generated_path = generate_key(
                key_type,
                public,
                self.private_key_label.path if key_type == "asymmetric" and public else "",
                self.algorithm_combo.currentText(),
                int(self.key_lengths_combo.currentText()),
                key_path
            )

            if key_type == "asymmetric":
                if public:
                    self.public_key_label.setPath(generated_path)
                else:
                    self.private_key_label.setPath(generated_path)
            else:
                self.key_label.setPath(generated_path)

            message = self.lang.t("key.generate.public.success") if public else self.lang.t("key.generate.private.success") if key_type == "asymmetric" else self.lang.t("key.generate.success")
            QMessageBox.information(self, self.lang.t("success"), message)
        except Exception as e:
            message = self.lang.t("key.error.10") if public else self.lang.t("key.error.9") if key_type == "asymmetric" else self.lang.t("key.error.8")
            QMessageBox.critical(self, self.lang.t("error"), message + str(e))

    def show_history_menu(self, target_label: "ClickablePathLabel", item_type: str, button: QPushButton):
        menu = QMenu(self)

        def refresh_menu():
            menu.close()
            QTimer.singleShot(0, lambda: self.show_history_menu(target_label, item_type, button))

        clear_widget = QWidget()
        clear_layout = QHBoxLayout(clear_widget)
        clear_layout.setContentsMargins(0, 0, 0, 0)
        message = self.lang.t("file.history.clear") if item_type == "file" else self.lang.t("key.history.clear") if item_type == "key" else self.lang.t("key.private.history.clear") if item_type == "private_key" else self.lang.t("key.public.history.clear")
        clear_label = QLabel(message)
        clear_label.setObjectName("historyLabel")
        clear_label.mousePressEvent = lambda event: (self.clear_history(), refresh_menu()) if event.button() == Qt.LeftButton else None
        clear_layout.addWidget(clear_label)
        clear_action = QWidgetAction(menu)
        clear_action.setDefaultWidget(clear_widget)
        menu.addAction(clear_action)
        menu.addSeparator()

        items = [i for i in self.history.load() if i.get("type") == item_type]

        if not items:
            empty_widget = QWidget()
            empty_layout = QHBoxLayout(empty_widget)
            empty_layout.setContentsMargins(0, 0, 0, 0)
            message = self.lang.t("file.history.empty") if item_type == "file" else self.lang.t("key.history.empty") if item_type == "key" else self.lang.t("key.private.history.empty") if item_type == "private_key" else self.lang.t("key.public.history.empty")
            empty_label = QLabel(message)
            empty_label.setObjectName("historyLabel")
            empty_layout.addWidget(empty_label)
            empty_action = QWidgetAction(menu)
            empty_action.setDefaultWidget(empty_widget)
            empty_action.setEnabled(False)
            menu.addAction(empty_action)
        else:
            for item in items:
                widget = QWidget()
                layout = QHBoxLayout(widget)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(0)
                label_text = f'{item["name"]} ({self.sizeof_fmt(item["size"])})'
                label = QLabel(label_text)
                label.setObjectName("historyLabel")
                label.setToolTip(item["path"])
                
                def on_label_click(path=item["path"], label_widget=target_label):
                    if os.path.exists(path):
                        label_widget.setPath(path)
                        self.history.add(path, item_type)
                        menu.close()
                    else:
                        message = self.lang.t("file.history.error") if item_type == "file" else self.lang.t("key.history.error") if item_type == "key" else self.lang.t("key.private.history.error") if item_type == "private_key" else self.lang.t("key.public.history.error")
                        QMessageBox.warning(self, self.lang.t("warning"), message.replace("$", path))
                        self.remove_history_item(path)
                        refresh_menu()

                label.mousePressEvent = lambda event, func=on_label_click: func() if event.button() == Qt.LeftButton else None

                remove_btn = QPushButton("×")
                remove_btn.setFixedSize(20, 20)
                remove_btn.setObjectName("removeHistoryButton")
                remove_btn.clicked.connect(lambda _, p=item["path"]: (self.remove_history_item(p), refresh_menu()))

                layout.addWidget(label)
                layout.addStretch()
                layout.addWidget(remove_btn)

                action = QWidgetAction(menu)
                action.setDefaultWidget(widget)
                menu.addAction(action)

        menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

    def clear_history(self):
        self.history.clear()

    def remove_history_item(self, path: str):
        self.history.remove(path)

    def start_encrypt_sign(self):
        self.start_crypto_task(encrypt=True)

    def start_decrypt_verify(self):
        self.start_crypto_task(encrypt=False)

    def start_crypto_task(self, encrypt: bool):
        self.current_encrypt_operation = encrypt
        self._crypto_start_time = time()
        self._memory_samples.clear()
        self._memory_timer.start(1000)

        if sys.platform == "win32":
            self.taskbar_progress.set_progress_type(ProgressType.NORMAL)

        algorithm = self.algorithm_combo.currentText()
        input_file = self.file_label.path

        options = QFileDialog.Option()
        filename, ext = os.path.splitext(os.path.basename(input_file))
        if encrypt:
            default_name = filename + ext + ".enc"
        else:
            if ext.lower() == ".enc":
                filename, ext2 = os.path.splitext(filename)
                default_name = filename + ".dec" + ext2
            else:
                default_name = filename + ".dec" + ext
        output_file, _ = QFileDialog.getSaveFileName(
            self,
            self.lang.t("file.save"),
            default_name,
            "All Files (*);;Encrypted Files (*.enc)",
            options=options
        )
        if not output_file:
            return
        
        self.encrypt_sign_button.setEnabled(False)
        self.decrypt_verify_button.setEnabled(False)

        params = {
            "mode": self.mode_combo.currentText() if hasattr(self, "mode_combo") else None,
            "key_length": int(self.key_lengths_combo.currentText()) if hasattr(self, "key_lengths_combo") else None,
            "hash": self.hashes_combo.currentText() if hasattr(self, "hashes_combo") else None,
            "padding": self.paddings_combo.currentText() if hasattr(self, "paddings_combo") else None,
            "curve": self.curves_combo.currentText() if hasattr(self, "curves_combo") else None,
        }

        self.worker = CryptoWorker(
            operation="encrypt" if encrypt else "decrypt",
            algorithm_name=algorithm,
            input_file=input_file,
            output_file=output_file,
            key_path=self.key_label.path,
            private_key_path=self.private_key_label.path,
            public_key_path=self.public_key_label.path,
            params=params,
            lang=self.lang
        )

        self.worker.progress.connect(self.progress_bar.setValue)

        if sys.platform == "win32":
            self.worker.progress.connect(lambda val: self.taskbar_progress.set_progress(val))

        self.worker.finished.connect(self.on_crypto_finished)
        self.worker.error.connect(self.on_crypto_error)

        self.progress_bar.setValue(0)
        self.cancel_button.setEnabled(True)
        self.worker.start()

    def cancel_operation(self):
        if hasattr(self, "worker") and self.worker.isRunning():
            self.worker.cancel()

        self.cancel_button.setEnabled(False)

        if sys.platform == "win32":
            self.taskbar_progress.reset()

        if hasattr(self, "_memory_timer"):
            self._memory_timer.stop()

        QMessageBox.information(
            self,
            self.lang.t("information"),
            self.lang.t("operations.cancelled")
        )

        self.progress_bar.setValue(0)
        self.update_operation_buttons_state()

    def on_crypto_finished(self):
        self.cancel_button.setEnabled(False)

        if sys.platform == "win32":
            self.taskbar_progress.flash_done()

        if hasattr(self, "_memory_timer"):
            self._memory_timer.stop()

        time_taken = time() - self._crypto_start_time if hasattr(self, "_crypto_start_time") and self._crypto_start_time else 0
        h = int(time_taken // 3600)
        m = int((time_taken % 3600) // 60)
        s = int(time_taken % 60)
        ms = int((time_taken - int(time_taken)) * 1000)
        formatted_time = f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"

        if hasattr(self, "_memory_samples") and self._memory_samples:
            avg_ram = self.sizeof_fmt(sum(self._memory_samples) / len(self._memory_samples))
        else:
            avg_ram = "—"

        if getattr(self, "current_encrypt_operation", True):
            message = self.lang.t("operations.encryption.success")
        else:
            message = self.lang.t("operations.decryption.success")

        QMessageBox.information(
            self,
            self.lang.t("success"),
            message.replace("$", formatted_time).replace("#", str(avg_ram))
        )

        self.progress_bar.setValue(0)
        self.update_operation_buttons_state()

    def on_crypto_error(self, message: str):
        self.cancel_button.setEnabled(False)

        if sys.platform == "win32":
            self.taskbar_progress.set_progress_type(ProgressType.ERROR)
            self.taskbar_progress.set_progress(0)

        if hasattr(self, "_memory_timer"):
            self._memory_timer.stop()

        QMessageBox.critical(
            self,
            self.lang.t("error"),
            message
        )

        self.progress_bar.setValue(0)
        self.update_operation_buttons_state()

    def load_theme_on_start(self):
        use_system = self.settings.value("use_system_theme", True, type=bool)

        if use_system:
            self.apply_system_theme()
        else:
            theme = self.settings.value("theme", "light")
            if theme == "dark":
                self.apply_dark_theme()
            else:
                self.apply_light_theme()

    def load_history_on_start(self):
        self.history = HistoryManager(self.settings)

    def load_stylesheet(self, path):
        with open(path, "r", encoding="utf-8") as f:
            self.setStyleSheet(f.read())

    def check_system_theme(self):
        if not self.settings.value("use_system_theme", True, type=bool):
            return

        is_dark = darkdetect.isDark()
        new_theme = "dark" if is_dark else "light"

        if new_theme != self.current_system_theme:
            self.current_system_theme = new_theme

            if new_theme == "dark":
                self.apply_dark_theme()
            else:
                self.apply_light_theme()

    def apply_system_theme(self):
        is_dark = darkdetect.isDark()
        self.current_system_theme = "dark" if is_dark else "light"

        if is_dark:
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

    def apply_light_theme(self):
        self.load_stylesheet("theme/light.qss")

    def apply_dark_theme(self):
        self.load_stylesheet("theme/dark.qss")

class ClickablePathLabel(QLabel):
    pathChanged = Signal()

    def __init__(self, label_type="file", placeholder=None, clear_button=None, parent=None):       
        self.label_type = label_type
        self.lang = parent.lang if parent and hasattr(parent, "lang") else None
        
        if placeholder is None:
            placeholder = self._default_placeholder()

        super().__init__(placeholder, parent)
        self.path = None
        self.clear_button = clear_button
        self.setObjectName("dragAndDropLabel")
        self.setAcceptDrops(True)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

    def _default_placeholder(self):
        if self.label_type == "file":
            return self.lang.t("file.none")
        if self.label_type == "key":
            return self.lang.t("key.none")
        if self.label_type == "private_key":
            return self.lang.t("key.private.none")
        if self.label_type == "public_key":
            return self.lang.t("key.public.none")

        return ""

    def setPath(self, path: str):
        if path and os.path.exists(path):
            self.path = path
            self.setText(path)
            self.setToolTip(f"{self.lang.t('path')}{path}\n{self.lang.t('size')}{self._safe_file_size_fmt(path)}\n{self.lang.t('double-click')}")
            if self.clear_button:
                self.clear_button.setEnabled(True)
            self.pathChanged.emit()
        else:
            self.clearPath()

    def clearPath(self):
        self.path = None
        self.setText(self._default_placeholder())
        self.setToolTip("")
        if self.clear_button:
            self.clear_button.setEnabled(False)
        self.pathChanged.emit()

    def mouseDoubleClickEvent(self, event):
        if self.path and os.path.exists(self.path):
            folder = os.path.dirname(self.path)
            if sys.platform == "win32":
                os.startfile(folder)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.setPath(path)
            event.acceptProposedAction()

    @staticmethod
    def _safe_file_size_fmt(path: str) -> str:
        try:
            num = os.path.getsize(path)
            for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
                if num < 1024.0:
                    return f"{num:.1f} {unit}"
                num /= 1024.0
            return f"{num:.1f} PiB"
        except OSError:
            return "—"

class ButtonOnlySpinBox(QSpinBox):
    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab):
            super().keyPressEvent(event)
            return
        event.ignore()

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

        self.language_combo = QComboBox()
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

        self.theme_combo = QComboBox()
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

        self.encryption_combo = QComboBox()
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

        self.decryption_combo = QComboBox()
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

        close_button = QPushButton(self.lang.t("settings.save.close"))
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

class HistoryManager:
    SETTINGS_KEY = "recent_items"

    def __init__(self, settings: QSettings):
        self.settings = settings

    def get_limit(self) -> int:
        return self.settings.value("history_limit", 10, type=int)

    def set_limit(self, limit: int):
        self.settings.setValue("history_limit", max(1, limit))
        self._trim()

    def load(self) -> list[dict]:
        return self.settings.value(self.SETTINGS_KEY, [], type=list)

    def save(self, items: list[dict]):
        self.settings.setValue(self.SETTINGS_KEY, items)

    def add(self, path: str, item_type: str):
        if not path or not os.path.exists(path):
            return

        items = self.load()
        items = [i for i in items if i["path"] != path]

        items.append({
            "path": path,
            "name": os.path.basename(path),
            "size": os.path.getsize(path),
            "type": item_type
        })

        self.save(items[-self.get_limit():])

    def remove(self, path: str):
        items = [i for i in self.load() if i["path"] != path]
        self.save(items)

    def clear(self):
        self.save([])

    def _trim(self):
        self.save(self.load()[-self.get_limit():])

class LanguageManager:
    def __init__(self, settings: QSettings, lang_dir="lang"):
        self.settings = settings
        self.lang_dir = lang_dir
        self.translations = {}
        self.current_lang = self.settings.value("language", "en")

        self.load_language(self.current_lang)

    def load_language(self, lang: str):
        path = os.path.join(self.lang_dir, f"{lang}.json")
        if not os.path.exists(path):
            return

        with open(path, "r", encoding="utf-8") as f:
            self.translations = json.load(f)

        self.current_lang = lang
        self.settings.setValue("language", lang)

    def t(self, key: str) -> str:
        return self.translations.get(key, key)