from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
)

from password_generator import (
    DEFAULT_PASSPHRASE_WORDS,
    MAX_PASSPHRASE_WORDS,
    MIN_PASSPHRASE_WORDS,
    PassphraseWordListError,
    generate_passphrase,
    generate_random_password,
)
from password_kdf import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
)

from .widgets import (
    AnimatedButton,
    AnimatedComboBox,
)


class PasswordGeneratorDialog(QDialog):
    def __init__(
        self,
        lang,
        parent=None,
    ):
        super().__init__(parent)

        self.lang = lang
        self.generated_password = None

        self.setWindowTitle(
            self.lang.t(
                "password.generator.title"
            )
        )
        self.setModal(True)
        self.setMinimumWidth(440)

        self._create_ui()

    def _create_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            16,
            14,
            16,
            14,
        )
        layout.setSpacing(10)

        layout.addWidget(
            QLabel(
                self.lang.t(
                    "password.generator.type"
                )
            )
        )

        self.type_combo = AnimatedComboBox()
        self.type_combo.addItem(
            self.lang.t(
                "password.generator.random"
            ),
            "random",
        )
        self.type_combo.addItem(
            self.lang.t(
                "password.generator.passphrase"
            ),
            "passphrase",
        )

        layout.addWidget(
            self.type_combo
        )

        self.length_label = QLabel()
        layout.addWidget(
            self.length_label
        )

        self.length_spinbox = QSpinBox()
        layout.addWidget(
            self.length_spinbox
        )

        self.uppercase_checkbox = QCheckBox(
            self.lang.t(
                "password.generator.uppercase"
            )
        )
        self.uppercase_checkbox.setChecked(
            True
        )

        self.numbers_checkbox = QCheckBox(
            self.lang.t(
                "password.generator.numbers"
            )
        )
        self.numbers_checkbox.setChecked(
            True
        )

        self.symbols_checkbox = QCheckBox(
            self.lang.t(
                "password.generator.symbols"
            )
        )
        self.symbols_checkbox.setChecked(
            True
        )

        layout.addWidget(
            self.uppercase_checkbox
        )
        layout.addWidget(
            self.numbers_checkbox
        )
        layout.addWidget(
            self.symbols_checkbox
        )

        layout.addWidget(
            QLabel(
                self.lang.t(
                    "password.generator.result"
                )
            )
        )

        self.password_input = QLineEdit()
        self.password_input.setMaxLength(
            PASSWORD_MAX_LENGTH
        )
        self.password_input.setPlaceholderText(
            self.lang.t(
                "password.generator.result.placeholder"
            )
        )

        layout.addWidget(
            self.password_input
        )

        buttons_layout = QHBoxLayout()
        buttons_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        cancel_button = AnimatedButton(
            self.lang.t(
                "operations.cancel"
            )
        )
        cancel_button.clicked.connect(
            self.reject
        )

        generate_button = AnimatedButton(
            self.lang.t(
                "password.generator.generate"
            )
        )
        generate_button.clicked.connect(
            self.generate
        )

        self.use_button = AnimatedButton(
            self.lang.t(
                "password.generator.use"
            )
        )
        self.use_button.setEnabled(False)
        self.use_button.clicked.connect(
            self.use_password
        )

        buttons_layout.addWidget(
            cancel_button
        )
        buttons_layout.addStretch()
        buttons_layout.addWidget(
            generate_button
        )
        buttons_layout.addWidget(
            self.use_button
        )

        layout.addLayout(
            buttons_layout
        )

        self.type_combo.currentIndexChanged.connect(
            self.update_generator_type
        )

        self.password_input.textChanged.connect(
            self.update_use_button
        )

        self.update_generator_type()

    def update_generator_type(self):
        generator_type = (
            self.type_combo.currentData()
        )

        if generator_type == "random":
            self.length_label.setText(
                self.lang.t(
                    "password.generator.length"
                )
            )

            self.length_spinbox.setRange(
                PASSWORD_MIN_LENGTH,
                PASSWORD_MAX_LENGTH,
            )
            self.length_spinbox.setValue(
                24
            )

            self.uppercase_checkbox.setChecked(
                True
            )
            self.numbers_checkbox.setChecked(
                True
            )
            self.symbols_checkbox.setChecked(
                True
            )

        else:
            self.length_label.setText(
                self.lang.t(
                    "password.generator.words"
                )
            )

            self.length_spinbox.setRange(
                MIN_PASSPHRASE_WORDS,
                MAX_PASSPHRASE_WORDS,
            )
            self.length_spinbox.setValue(
                DEFAULT_PASSPHRASE_WORDS
            )

            self.uppercase_checkbox.setChecked(
                False
            )
            self.numbers_checkbox.setChecked(
                False
            )
            self.symbols_checkbox.setChecked(
                False
            )

    def generate(self):
        try:
            if (
                self.type_combo.currentData()
                == "random"
            ):
                password = (
                    generate_random_password(
                        self.length_spinbox.value(),
                        self.uppercase_checkbox.isChecked(),
                        self.numbers_checkbox.isChecked(),
                        self.symbols_checkbox.isChecked(),
                    )
                )
            else:
                password = generate_passphrase(
                    self.length_spinbox.value(),
                    self.uppercase_checkbox.isChecked(),
                    self.numbers_checkbox.isChecked(),
                    self.symbols_checkbox.isChecked(),
                )

        except PassphraseWordListError:
            QMessageBox.warning(
                self,
                self.lang.t(
                    "warning"
                ),
                self.lang.t(
                    "password.generator.error.wordlist"
                ),
            )
            return

        except ValueError:
            QMessageBox.warning(
                self,
                self.lang.t(
                    "warning"
                ),
                self.lang.t(
                    "password.generator.error"
                ),
            )
            return

        self.password_input.setText(
            password
        )

        self.password_input.setFocus()
        self.password_input.selectAll()

    def update_use_button(self):
        self.use_button.setEnabled(
            bool(
                self.password_input.text()
            )
        )

    def use_password(self):
        password = self.password_input.text()

        if len(password) < PASSWORD_MIN_LENGTH:
            message = self.lang.t(
                "password.error.min.length"
            ).replace(
                "$",
                str(PASSWORD_MIN_LENGTH),
            )

            QMessageBox.warning(
                self,
                self.lang.t("warning"),
                message,
            )
            return

        if len(password) > PASSWORD_MAX_LENGTH:
            message = self.lang.t(
                "password.error.max.length"
            ).replace(
                "$",
                str(PASSWORD_MAX_LENGTH),
            )

            QMessageBox.warning(
                self,
                self.lang.t("warning"),
                message,
            )
            return

        self.generated_password = password
        self.accept()