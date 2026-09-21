import warnings
from time import time
import os
import sys

from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import darkdetect
from psutil import Process
from PySide6.QtCore import QLocale, QSettings, Qt, QTimer
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFileDialog, QComboBox, QProgressBar, QGroupBox, QSizePolicy,
    QMessageBox, QMenu, QWidgetAction,
)
from PyTaskbar import ProgressType, TaskbarProgress

from algorithms import ALGORITHMS
from crypto_worker import CryptoWorker
from file_format import read_header
from key_generation_worker import KeyGenerationWorker

from .algorithm_info import AlgorithmInfoDialog
from .history_manager import HistoryManager
from .language_manager import LanguageManager
from .settings_dialog import SettingsDialog
from .widgets import (
    AnimatedButton, AnimatedComboBox, ClickablePathLabel, STREAMING_ROLE, StreamingComboDelegate, ALGORITHM_HEADER_ROLE
)


SIGNATURE_ALGORITHMS = {
    "RSA-PSS",
    "EdDSA",
    "ECDSA",
    "ML-DSA",
    "SLH-DSA",
}


class MainWindow(QMainWindow):
    settings = QSettings("Vyroxes", "File Encryption and Decryption")

    def __init__(self):
        super().__init__()

        self._initialize_default_settings()

        self.lang = LanguageManager(self.settings)

        self.setWindowTitle(self.lang.t("app.title"))
        self.setMinimumSize(600, 578)
        self.resize(600, 578)

        self.key_generation_worker = None

        self._process = Process(os.getpid())
        self._memory_samples = []
        self._crypto_start_time = None
        self._memory_timer = QTimer()
        self._memory_timer.timeout.connect(self._sample_memory)

        self._history_menu = None
        self._history_menu_button = None
        self._ignore_history_button = None

        if sys.platform == "win32":
            hwnd = int(self.winId())
            self.taskbar_progress = TaskbarProgress(hwnd)
            self.taskbar_progress.set_progress_type(ProgressType.NORMAL)
            self.taskbar_progress.set_progress(0)

        central_widget = QWidget()
        general_layout = QVBoxLayout(central_widget)

        header_layout = QHBoxLayout()
        header_layout.addStretch()

        self.settings_button = AnimatedButton(self.lang.t("settings.title"))
        self.settings_button.setObjectName("settingsButton")
        self.settings_button.clicked.connect(self.open_settings)

        header_layout.addWidget(self.settings_button)
        general_layout.addLayout(header_layout)

        self.file_signature_widget = QWidget()
        self.file_signature_layout = QHBoxLayout(self.file_signature_widget)
        self.file_signature_layout.setContentsMargins(0, 0, 0, 0)

        self.file_group = self.create_file_section()
        self.signature_group = self.create_signature_section()

        self.file_signature_layout.addWidget(self.file_group, 1)
        self.file_signature_layout.addWidget(self.signature_group, 1)

        self.signature_group.hide()

        general_layout.addWidget(self.file_signature_widget)
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

    def create_signature_section(self):
        group = QGroupBox(self.lang.t("signature.group"))
        group.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        layout = QVBoxLayout(group)

        row_layout, self.clear_signature_button = self.create_select_row(
            self.lang.t("signature.select"),
            self.select_signature,
            self.clear_signature,
            lambda btn: self.show_history_menu(
                self.signature_label,
                "signature",
                btn,
            ),
        )

        self.signature_label = ClickablePathLabel(
            "signature",
            clear_button=self.clear_signature_button,
            parent=self,
        )

        self.signature_label.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred,
        )

        self.signature_label.pathChanged.connect(
            self.update_operation_buttons_state
        )

        layout.addWidget(self.signature_label)
        layout.addLayout(row_layout)

        return group

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

        history_button = AnimatedButton("☰")
        history_button.setFixedSize(28, 28)
        history_button.setObjectName("historyButton")

        if history_callback:
            history_button.clicked.connect(
                lambda: history_callback(history_button)
            )

        select_button = AnimatedButton(text)

        clear_button = AnimatedButton("×")
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
        group.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
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
        self.key_group.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
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

        self.generate_key_button = AnimatedButton(self.lang.t("key.generate"))
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
        
        self.generate_private_key_button = AnimatedButton(self.lang.t("key.generate.private"))
        self.generate_private_key_button.clicked.connect(lambda: self.generate_key("asymmetric", False))
        
        self.generate_public_key_button = AnimatedButton(self.lang.t("key.generate.public"))
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

        self.algorithm_combo = AnimatedComboBox()
        self.algorithm_combo.setObjectName("algorithmCombo")
        self.algorithm_combo.setItemDelegate(StreamingComboDelegate(self.algorithm_combo))
        self.algorithm_combo.setLabelDrawingMode(QComboBox.LabelDrawingMode.UseDelegate)

        def add_algorithm_header(text):
            self.algorithm_combo.addItem(text)

            index = self.algorithm_combo.count() - 1

            self.algorithm_combo.setItemData(
                index,
                True,
                ALGORITHM_HEADER_ROLE,
            )

            item = self.algorithm_combo.model().item(index)

            if item:
                item.setEnabled(False)
                item.setSelectable(False)


        def add_algorithm_item(
            algorithm_name,
            algorithm,
        ):
            self.algorithm_combo.addItem(
                algorithm_name
            )

            mode_streaming = algorithm.get(
                "mode_streaming"
            )

            if mode_streaming is not None:
                is_streaming = any(
                    mode_streaming.values()
                )
            else:
                is_streaming = algorithm.get(
                    "streaming",
                    False,
                )

            index = self.algorithm_combo.count() - 1

            self.algorithm_combo.setItemData(
                index,
                is_streaming,
                STREAMING_ROLE,
            )


        add_algorithm_header(
            self.lang.t(
                "algorithm.category.encryption"
            )
        )

        for algorithm_name, algorithm in ALGORITHMS.items():
            if algorithm_name not in SIGNATURE_ALGORITHMS:
                add_algorithm_item(
                    algorithm_name,
                    algorithm,
                )

        add_algorithm_header(
            self.lang.t(
                "algorithm.category.signatures"
            )
        )

        for algorithm_name, algorithm in ALGORITHMS.items():
            if algorithm_name in SIGNATURE_ALGORITHMS:
                add_algorithm_item(
                    algorithm_name,
                    algorithm,
                )

        aes_index = self.algorithm_combo.findText("AES")

        if aes_index >= 0:
            self.algorithm_combo.setCurrentIndex(aes_index)

        self.algorithm_combo.currentTextChanged.connect(self.update_algorithm_params)

        self.algorithm_info_button = AnimatedButton("?")
        self.algorithm_info_button.setFixedSize(28, 28)
        self.algorithm_info_button.setObjectName("infoButton")
        self.algorithm_info_button.clicked.connect(self.show_algorithm_info)

        self.toggle_params_button = AnimatedButton(self.lang.t("algorithm.show.settings"))
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

    def show_algorithm_info(self):
        algorithm_name = self.algorithm_combo.currentText()
        algorithm = ALGORITHMS.get(algorithm_name)

        if not algorithm:
            return

        selected_mode = None

        if algorithm.get("modes") and hasattr(self, "mode_combo"):
            selected_mode = self.mode_combo.currentText()

        dialog = AlgorithmInfoDialog(
            algorithm_name,
            algorithm,
            selected_mode,
            self.lang,
            self,
        )
        dialog.exec()

    def create_operations_section(self):
        group = QGroupBox(self.lang.t("operations.group"))
        layout = QVBoxLayout(group)

        buttons_layout = QHBoxLayout()

        self.encrypt_sign_button = AnimatedButton(self.lang.t("operations.encrypt"))
        self.encrypt_sign_button.clicked.connect(self.start_encrypt_sign)
        self.encrypt_sign_button.setEnabled(False)
        self.decrypt_verify_button = AnimatedButton(self.lang.t("operations.decrypt"))
        self.decrypt_verify_button.clicked.connect(self.start_decrypt_verify)
        self.decrypt_verify_button.setEnabled(False)

        buttons_layout.addWidget(self.encrypt_sign_button)
        buttons_layout.addWidget(self.decrypt_verify_button)

        self.cancel_button = AnimatedButton(self.lang.t("operations.cancel"))
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

        self.signature_group.setVisible(algorithm_name in SIGNATURE_ALGORITHMS)

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

        for attr in (
            "key_lengths_combo",
            "mode_combo",
            "hashes_combo",
            "paddings_combo",
            "curves_combo",
            "parameter_sets_combo",
        ):
            if hasattr(self, attr):
                delattr(self, attr)

        left_column = QVBoxLayout()
        middle_column = QVBoxLayout()
        right_column = QVBoxLayout()

        if algorithm["type"] == "symmetric":
            key_lengths = algorithm.get("key_lengths", [])
            modes = algorithm.get("modes", [])

            if key_lengths:
                key_lengths_label = QLabel(self.lang.t("algorithm.key.length"))
                self.key_lengths_combo = AnimatedComboBox()
                self.key_lengths_combo.addItems([str(k) for k in key_lengths])
                if len(key_lengths) == 1:
                    self.key_lengths_combo.setEnabled(False)
                left_column.addWidget(key_lengths_label)
                left_column.addWidget(self.key_lengths_combo)

            if modes:
                mode_label = QLabel(self.lang.t("algorithm.mode"))
                self.mode_combo = AnimatedComboBox()
                self.mode_combo.setItemDelegate(StreamingComboDelegate(self.mode_combo))
                self.mode_combo.setLabelDrawingMode(QComboBox.LabelDrawingMode.UseDelegate)

                mode_streaming = algorithm.get("mode_streaming", {})

                for mode_name in modes:
                    self.mode_combo.addItem(mode_name)

                    index = self.mode_combo.count() - 1
                    is_streaming = mode_streaming.get(
                        mode_name,
                        algorithm.get("streaming", False),
                    )

                    self.mode_combo.setItemData(index, is_streaming, STREAMING_ROLE)

                if len(modes) == 1:
                    self.mode_combo.setEnabled(False)

                right_column.addWidget(mode_label)
                right_column.addWidget(self.mode_combo)

            if algorithm_name == "AES":
                def sync_aes_key_lengths(mode_name):
                    key_lengths = algorithm.get("mode_key_lengths", {}).get(
                        mode_name,
                        algorithm.get("key_lengths", [])
                    )

                    self.key_lengths_combo.clear()
                    self.key_lengths_combo.addItems([str(k) for k in key_lengths])
                    self.key_lengths_combo.setCurrentIndex(0)

                sync_aes_key_lengths(self.mode_combo.currentText())
                self.mode_combo.currentTextChanged.connect(sync_aes_key_lengths)

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
            parameter_sets = algorithm.get("parameter_sets", [])

            if curves:
                curves_label = QLabel(self.lang.t("algorithm.curve"))
                self.curves_combo = AnimatedComboBox()
                self.curves_combo.addItems(curves)
                if len(curves) == 1:
                    self.curves_combo.setEnabled(False)
                left_column.addWidget(curves_label)
                left_column.addWidget(self.curves_combo)

            if parameter_sets:
                parameter_sets_label = QLabel(
                    self.lang.t("algorithm.parameter.set")
                )

                self.parameter_sets_combo = AnimatedComboBox()
                self.parameter_sets_combo.addItems(parameter_sets)

                if len(parameter_sets) == 1:
                    self.parameter_sets_combo.setEnabled(False)

                left_column.addWidget(parameter_sets_label)
                left_column.addWidget(
                    self.parameter_sets_combo
                )

            if key_lengths:
                key_lengths_label = QLabel(self.lang.t("algorithm.key.length"))
                self.key_lengths_combo = AnimatedComboBox()
                self.key_lengths_combo.addItems([str(k) for k in key_lengths])
                if len(key_lengths) == 1:
                    self.key_lengths_combo.setEnabled(False)
                left_column.addWidget(key_lengths_label)
                left_column.addWidget(self.key_lengths_combo)

            if paddings:
                paddings_label = QLabel(self.lang.t("algorithm.padding"))
                self.paddings_combo = AnimatedComboBox()
                self.paddings_combo.addItems(paddings)
                if len(paddings) == 1:
                    self.paddings_combo.setEnabled(False)
                middle_column.addWidget(paddings_label)
                middle_column.addWidget(self.paddings_combo)

            if hashes:
                hashes_label = QLabel(self.lang.t("algorithm.hash"))
                self.hashes_combo = AnimatedComboBox()
                self.hashes_combo.addItems(hashes)
                if len(hashes) == 1:
                    self.hashes_combo.setEnabled(False)
                right_column.addWidget(hashes_label)
                right_column.addWidget(self.hashes_combo)

            if algorithm_name == "ECDSA":
                def sync_ecdsa_hash(curve_name):
                    defaults = {
                        "P-521 (secp521r1)": "SHA3-512",
                        "P-384 (secp384r1)": "SHA3-384",
                        "P-256 (secp256r1)": "SHA3-256",
                    }

                    hash_name = defaults.get(curve_name)

                    if not hash_name:
                        return

                    index = self.hashes_combo.findText(hash_name)

                    if index >= 0:
                        self.hashes_combo.setCurrentIndex(index)

                sync_ecdsa_hash(
                    self.curves_combo.currentText()
                )

                self.curves_combo.currentTextChanged.connect(
                    sync_ecdsa_hash
                )

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

        algorithm_name = self.algorithm_combo.currentText()
        algorithm = ALGORITHMS.get(algorithm_name)

        if not algorithm:
            self.encrypt_sign_button.setEnabled(False)
            self.decrypt_verify_button.setEnabled(False)
            return

        file_path = self.file_label.path
        is_file_selected = bool(file_path)
        is_enc_file = is_file_selected and file_path.lower().endswith(".enc")

        if algorithm_name in SIGNATURE_ALGORITHMS:
            self.encrypt_sign_button.setText(
                self.lang.t("operations.sign")
            )
            self.decrypt_verify_button.setText(
                self.lang.t("operations.verify")
            )

            self.encrypt_sign_button.setEnabled(
                is_file_selected
                and bool(self.private_key_label.path)
            )

            self.decrypt_verify_button.setEnabled(
                is_file_selected
                and bool(self.public_key_label.path)
                and bool(self.signature_label.path)
            )

            return

        self.encrypt_sign_button.setText(
            self.lang.t("operations.encrypt")
        )
        self.decrypt_verify_button.setText(
            self.lang.t("operations.decrypt")
        )

        if algorithm_name == "RSA-OAEP":
            self.encrypt_sign_button.setEnabled(
                is_file_selected
                and bool(self.public_key_label.path)
                and not is_enc_file
            )

            self.decrypt_verify_button.setEnabled(
                is_file_selected
                and bool(self.private_key_label.path)
                and is_enc_file
            )

            return

        has_key = bool(self.key_label.path)

        self.encrypt_sign_button.setEnabled(
            is_file_selected
            and has_key
            and not is_enc_file
        )

        self.decrypt_verify_button.setEnabled(
            is_file_selected
            and has_key
            and is_enc_file
        )

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

    def load_metadata_from_enc(self, file_path: str) -> tuple[dict, dict]:
        try:
            with open(file_path, "rb") as file:
                metadata, _ = read_header(file, lang=self.lang)

            return metadata, metadata.get("params", {})

        except Exception as exc:
            QMessageBox.warning(self, self.lang.t("warning"), str(exc))
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

    def select_signature(self):
        options = QFileDialog.Option()

        path, _ = QFileDialog.getOpenFileName(
            self,
            self.lang.t("signature.select"),
            "",
            "Signature Files (*.sig);;All Files (*)",
            options=options,
        )

        if path:
            self.signature_label.setPath(path)
            self.history.add(path, "signature")

    def clear_signature(self):
        self.signature_label.clearPath()

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
        if (
            self.key_generation_worker
            and self.key_generation_worker.isRunning()
        ):
            return

        if key_type == "symmetric" and public:
            return

        if (
            key_type == "asymmetric"
            and public
            and not self.private_key_label.path
        ):
            QMessageBox.warning(
                self,
                self.lang.t("warning"),
                self.lang.t("key.error.2"),
            )
            return

        options = QFileDialog.Option()

        if key_type == "asymmetric" and not public:
            key_path, _ = QFileDialog.getSaveFileName(
                self,
                self.lang.t("key.save.private"),
                self.lang.t("key.private.file"),
                "Key Files (*.key);;All Files (*)",
                options=options,
            )

        elif key_type == "asymmetric" and public:
            key_path, _ = QFileDialog.getSaveFileName(
                self,
                self.lang.t("key.save.public"),
                self.lang.t("key.public.file"),
                "Key Files (*.key);;All Files (*)",
                options=options,
            )

        else:
            key_path, _ = QFileDialog.getSaveFileName(
                self,
                self.lang.t("key.save"),
                self.lang.t("key.file"),
                "Key Files (*.key);;All Files (*)",
                options=options,
            )

        if not key_path:
            return

        private_key_path = (
            self.private_key_label.path
            if key_type == "asymmetric" and public
            else ""
        )

        algorithm_name = self.algorithm_combo.currentText()

        key_length_bits = (
            int(self.key_lengths_combo.currentText())
            if hasattr(self, "key_lengths_combo")
            else None
        )

        curve = (
            self.curves_combo.currentText()
            if hasattr(self, "curves_combo")
            else None
        )

        mode = (
            self.mode_combo.currentText()
            if hasattr(self, "mode_combo")
            else None
        )

        self.key_generation_worker = KeyGenerationWorker(
            key_type=key_type,
            public=public,
            private_key_path=private_key_path,
            algorithm_name=algorithm_name,
            key_length_bits=key_length_bits,
            output_path=key_path,
            mode=mode,
            lang=self.lang,
            curve=curve,
        )

        self.key_generation_worker.generated.connect(
            self.on_key_generated
        )

        self.key_generation_worker.failed.connect(
            self.on_key_generation_error
        )

        self.key_generation_worker.finished.connect(
            self.on_key_generation_finished
        )

        self.set_key_generation_running(True)

        self.key_generation_worker.start()

    def on_key_generated(
        self,
        generated_path: str,
        key_type: str,
        public: bool,
    ):
        if key_type == "asymmetric":
            if public:
                self.public_key_label.setPath(
                    generated_path
                )
            else:
                self.private_key_label.setPath(
                    generated_path
                )
        else:
            self.key_label.setPath(
                generated_path
            )

        if key_type == "asymmetric":
            if public:
                self.history.add(
                    generated_path,
                    "public_key",
                )
            else:
                self.history.add(
                    generated_path,
                    "private_key",
                )
        else:
            self.history.add(
                generated_path,
                "key",
            )

        if key_type == "asymmetric":
            message = (
                self.lang.t(
                    "key.generate.public.success"
                )
                if public
                else self.lang.t(
                    "key.generate.private.success"
                )
            )
        else:
            message = self.lang.t(
                "key.generate.success"
            )

        QMessageBox.information(
            self,
            self.lang.t("success"),
            message,
        )

    def on_key_generation_error(
        self,
        error: str,
        key_type: str,
        public: bool,
    ):
        if key_type == "asymmetric":
            message = (
                self.lang.t("key.error.10")
                if public
                else self.lang.t("key.error.9")
            )
        else:
            message = self.lang.t(
                "key.error.8"
            )

        QMessageBox.critical(
            self,
            self.lang.t("error"),
            message + error,
        )

    def on_key_generation_finished(self):
        self.set_key_generation_running(False)

        if self.key_generation_worker:
            self.key_generation_worker.deleteLater()
            self.key_generation_worker = None

    def set_key_generation_running(self, running: bool):
        self.key_group.setEnabled(not running)
        self.algorithm_group.setEnabled(not running)

    @staticmethod
    def _history_translation_key(item_type: str, action: str) -> str:
        prefixes = {
            "file": "file",
            "key": "key",
            "private_key": "key.private",
            "public_key": "key.public",
            "signature": "signature",
        }

        return f"{prefixes[item_type]}.history.{action}"

    def show_history_menu(self, target_label: "ClickablePathLabel", item_type: str, button: AnimatedButton):
        if self._ignore_history_button is button:
            self._ignore_history_button = None
            return

        menu = QMenu(self)

        self._history_menu = menu
        self._history_menu_button = button

        def refresh_menu():
            menu.close()
            QTimer.singleShot(0, lambda: self.show_history_menu(target_label, item_type, button))

        clear_widget = QWidget()
        clear_layout = QHBoxLayout(clear_widget)
        clear_layout.setContentsMargins(0, 0, 0, 0)
        message = self.lang.t(self._history_translation_key(item_type, "clear"))
        clear_label = QLabel(message)
        clear_label.setObjectName("historyLabel")
        clear_label.mousePressEvent = lambda event: (self.clear_history(item_type), refresh_menu()) if event.button() == Qt.LeftButton else None
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
            message = self.lang.t(self._history_translation_key(item_type, "empty"))
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
                label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
                
                def on_label_click(path=item["path"], label_widget=target_label):
                    if os.path.exists(path):
                        label_widget.setPath(path)
                        self.history.add(path, item_type)
                        menu.close()
                    else:
                        message = self.lang.t("file.history.error") if item_type == "file" else self.lang.t("key.history.error") if item_type == "key" else self.lang.t("key.private.history.error") if item_type == "private_key" else self.lang.t("key.public.history.error")
                        QMessageBox.warning(self, self.lang.t("warning"), message.replace("$", path))
                        self.remove_history_item(path, item_type)
                        refresh_menu()

                label.mousePressEvent = lambda event, func=on_label_click: func() if event.button() == Qt.LeftButton else None

                remove_btn = QPushButton("×")
                remove_btn.setFixedWidth(32)
                remove_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
                remove_btn.setObjectName("removeHistoryButton")
                remove_btn.clicked.connect(lambda _, p=item["path"], t=item_type: (self.remove_history_item(p, t), refresh_menu()))

                layout.addWidget(label, 1)
                layout.addWidget(remove_btn)

                action = QWidgetAction(menu)
                action.setDefaultWidget(widget)
                menu.addAction(action)

        def on_menu_hide():
            if button.rect().contains(button.mapFromGlobal(QCursor.pos())):
                self._ignore_history_button = button

            if self._history_menu is menu:
                self._history_menu = None
                self._history_menu_button = None

        menu.aboutToHide.connect(on_menu_hide)
        menu.popup(button.mapToGlobal(button.rect().bottomLeft()))

    def clear_history(self, item_type: str):
        self.history.clear(item_type)

    def remove_history_item(self, path: str, item_type: str):
        self.history.remove(path, item_type)

    def start_encrypt_sign(self):
        algorithm = self.algorithm_combo.currentText()

        operation = (
            "sign"
            if algorithm in SIGNATURE_ALGORITHMS
            else "encrypt"
        )

        self.start_crypto_task(operation)

    def start_decrypt_verify(self):
        algorithm = self.algorithm_combo.currentText()

        operation = (
            "verify"
            if algorithm in SIGNATURE_ALGORITHMS
            else "decrypt"
        )

        self.start_crypto_task(operation)

    def start_crypto_task(self, operation: str):
        self._operation_cancelled = False
        self.current_operation = operation

        algorithm = self.algorithm_combo.currentText()
        input_file = self.file_label.path

        output_file = None

        if operation == "sign":
            options = QFileDialog.Option()

            default_name = os.path.basename(input_file) + ".sig"

            output_file, _ = QFileDialog.getSaveFileName(
                self,
                self.lang.t("signature.save"),
                default_name,
                "Signature Files (*.sig);;All Files (*)",
                options=options,
            )

            if not output_file:
                return

            if not output_file.lower().endswith(".sig"):
                output_file += ".sig"

        elif operation in ("encrypt", "decrypt"):
            options = QFileDialog.Option()

            input_name = os.path.basename(input_file)
            filename, ext = os.path.splitext(input_name)

            if operation == "encrypt":
                default_name = input_name + ".enc"

                output_file, _ = QFileDialog.getSaveFileName(
                    self,
                    self.lang.t("file.save"),
                    default_name,
                    "Encrypted Files (*.enc);;All Files (*)",
                    options=options,
                )

                if not output_file:
                    return

                if not output_file.lower().endswith(".enc"):
                    output_file += ".enc"

            else:
                if ext.lower() == ".enc":
                    default_name = filename
                    original_ext = os.path.splitext(filename)[1]
                else:
                    default_name = filename + ".dec" + ext
                    original_ext = ext

                if original_ext:
                    file_filter = (
                        f"{self.lang.t('file.original.type')} "
                        f"(*{original_ext});;"
                        f"{self.lang.t('file.all.types')} (*)"
                    )
                else:
                    file_filter = (
                        f"{self.lang.t('file.all.types')} (*)"
                    )

                output_file, _ = QFileDialog.getSaveFileName(
                    self,
                    self.lang.t("file.save"),
                    default_name,
                    file_filter,
                    options=options,
                )

                if not output_file:
                    return

        self._crypto_start_time = time()
        self._memory_samples.clear()
        self._sample_memory()
        self._memory_timer.start(500)

        if sys.platform == "win32":
            self.taskbar_progress.set_progress_type(
                ProgressType.NORMAL
            )
            self.taskbar_progress.set_progress(0)

        self.encrypt_sign_button.setEnabled(False)
        self.decrypt_verify_button.setEnabled(False)

        params = {
            "mode": (
                self.mode_combo.currentText()
                if hasattr(self, "mode_combo")
                else None
            ),
            "key_length": (
                int(self.key_lengths_combo.currentText())
                if hasattr(self, "key_lengths_combo")
                else None
            ),
            "hash": (
                self.hashes_combo.currentText()
                if hasattr(self, "hashes_combo")
                else None
            ),
            "padding": (
                self.paddings_combo.currentText()
                if hasattr(self, "paddings_combo")
                else None
            ),
            "curve": (
                self.curves_combo.currentText()
                if hasattr(self, "curves_combo")
                else None
            ),
            "parameter_set": (
                self.parameter_sets_combo.currentText()
                if hasattr(self, "parameter_sets_combo")
                else None
            ),
        }

        if algorithm in ("RSA-OAEP", "ML-KEM"):
            crypto_key_path = (
                self.public_key_label.path
                if operation == "encrypt"
                else self.private_key_label.path
            )
        else:
            crypto_key_path = self.key_label.path

        self.worker = CryptoWorker(
            operation=operation,
            algorithm_name=algorithm,
            input_file=input_file,
            output_file=output_file,
            key_path=crypto_key_path,
            private_key_path=self.private_key_label.path,
            public_key_path=self.public_key_label.path,
            signature_path=self.signature_label.path,
            params=params,
            lang=self.lang,
        )

        self.worker.progress.connect(
            self.on_crypto_progress
        )

        self.worker.finished.connect(
            self.on_crypto_finished
        )

        self.worker.verification_finished.connect(
            self.on_verification_finished
        )

        self.worker.error.connect(
            self.on_crypto_error
        )

        self.progress_bar.setValue(0)
        self.cancel_button.setEnabled(True)
        self.worker.start()

    def on_crypto_progress(self, value: int):
        if getattr(self, "_operation_cancelled", False):
            return

        self.progress_bar.setValue(value)

        if sys.platform == "win32":
            self.taskbar_progress.set_progress(value)

    def cancel_operation(self):
        self._operation_cancelled = True

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

    def on_crypto_finished(self, output_file=""):
        self.cancel_button.setEnabled(False)

        if sys.platform == "win32":
            self.taskbar_progress.flash_done()

        self._sample_memory()

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

        operation = getattr(
            self,
            "current_operation",
            "encrypt",
        )

        if operation == "encrypt":
            message = self.lang.t(
                "operations.encryption.success"
            )
        elif operation == "decrypt":
            message = self.lang.t(
                "operations.decryption.success"
            )
        elif operation == "sign":
            message = self.lang.t(
                "operations.signing.success"
            )
        else:
            message = self.lang.t(
                "operations.encryption.success"
            )

        if operation == "sign" and output_file:
            self.signature_label.setPath(output_file)
            self.history.add(output_file, "signature")

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

    def on_verification_finished(self, valid: bool):
        self.cancel_button.setEnabled(False)

        if hasattr(self, "_memory_timer"):
            self._memory_timer.stop()

        if valid:
            if sys.platform == "win32":
                self.taskbar_progress.flash_done()

            QMessageBox.information(
                self,
                self.lang.t("success"),
                self.lang.t("operations.verification.valid"),
            )
        else:
            if sys.platform == "win32":
                self.taskbar_progress.set_progress_type(
                    ProgressType.ERROR
                )
                self.taskbar_progress.set_progress(100)

            QMessageBox.critical(
                self,
                self.lang.t("error"),
                self.lang.t("operations.verification.invalid"),
            )

        if sys.platform == "win32":
            self.taskbar_progress.reset()

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