from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QHeaderView, QLabel, QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from .widgets import AnimatedButton, DescriptionDelegate


ALGORITHM_INFO = {
    "AES": {
        "primitive": "algorithm.info.primitive.block",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": "128",
        "description": "algorithm.info.description.aes",
    },
    "ASCON": {
        "primitive": "algorithm.info.primitive.permutation.aead",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": None,
        "description": "algorithm.info.description.ascon",
    },
    "Serpent-HMAC": {
        "primitive": "algorithm.info.primitive.block.mac",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": "128",
        "description": "algorithm.info.description.serpent",
    },
    "Camellia": {
        "primitive": "algorithm.info.primitive.block",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": "128",
        "description": "algorithm.info.description.camellia",
    },
    "3DES": {
        "primitive": "algorithm.info.primitive.block",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": "64",
        "description": "algorithm.info.description.3des",
    },
    "ChaCha20-Poly1305": {
        "primitive": "algorithm.info.primitive.stream.aead",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": None,
        "description": "algorithm.info.description.chacha",
    },
    "XChaCha20-Poly1305": {
        "primitive": "algorithm.info.primitive.stream.aead",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": None,
        "description": "algorithm.info.description.xchacha",
    },
    "Salsa20": {
        "primitive": "algorithm.info.primitive.stream",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": None,
        "description": "algorithm.info.description.salsa20",
    },
    "Threefish-Skein-MAC": {
        "primitive": "algorithm.info.primitive.block.mac",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": "256 / 512 / 1024",
        "description": "algorithm.info.description.threefish",
    },
    "RSA-OAEP": {
        "primitive": "algorithm.info.primitive.asymmetric.encryption",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": None,
        "description": "algorithm.info.description.rsa.oaep",
    },
    "RSA-PSS": {
        "primitive": "algorithm.info.primitive.asymmetric.signature",
        "operations": "algorithm.info.operation.sign.verify",
        "block_size": None,
        "description": "algorithm.info.description.rsa.pss",
    },
    "EdDSA": {
        "primitive": "algorithm.info.primitive.signature",
        "operations": "algorithm.info.operation.sign.verify",
        "block_size": None,
        "description": "algorithm.info.description.eddsa",
    },
    "ECDSA": {
        "primitive": "algorithm.info.primitive.signature",
        "operations": "algorithm.info.operation.sign.verify",
        "block_size": None,
        "description": "algorithm.info.description.ecdsa",
    },
    "ML-KEM": {
        "primitive": "algorithm.info.primitive.kem",
        "operations": "algorithm.info.operation.encrypt.decrypt",
        "block_size": None,
        "description": "algorithm.info.description.ml.kem",
    },
    "ML-DSA": {
        "primitive": "algorithm.info.primitive.pqc.signature",
        "operations": "algorithm.info.operation.sign.verify",
        "block_size": None,
        "description": "algorithm.info.description.ml.dsa",
    },
    "SLH-DSA": {
        "primitive": "algorithm.info.primitive.hash.signature",
        "operations": "algorithm.info.operation.sign.verify",
        "block_size": None,
        "description": "algorithm.info.description.slh.dsa",
    },
}

MODE_INFO = {
    "AES": {
        "GCM (AEAD)": ("AEAD", True, "algorithm.info.mode.gcm"),
        "EAX (AEAD)": ("AEAD", True, "algorithm.info.mode.eax"),
        "SIV (AEAD)": ("AEAD", True, "algorithm.info.mode.siv"),
        "CCM (AEAD)": ("AEAD", True, "algorithm.info.mode.ccm"),
        "OCB (AEAD)": ("AEAD", True, "algorithm.info.mode.ocb"),
        "CTR": ("CTR", False, "algorithm.info.mode.ctr"),
        "CBC": ("CBC", False, "algorithm.info.mode.cbc"),
        "ECB": ("ECB", False, "algorithm.info.mode.ecb"),
    },
    "ASCON": {
        "Ascon-128 (AEAD)": (
            "AEAD",
            True,
            "algorithm.info.mode.ascon.128.aead",
        ),
    },
    "Serpent-HMAC": {
        "CBC + HMAC-SHA256": (
            "Encrypt-then-MAC",
            True,
            "algorithm.info.mode.serpent.cbc.hmac",
        ),
    },
    "Camellia": {
        "CFB": ("CFB", False, "algorithm.info.mode.cfb"),
        "CBC": ("CBC", False, "algorithm.info.mode.cbc"),
    },
    "3DES": {
        "EAX (AEAD)": ("AEAD", True, "algorithm.info.mode.eax"),
        "CTR": ("CTR", False, "algorithm.info.mode.ctr"),
        "CFB": ("CFB", False, "algorithm.info.mode.cfb"),
        "OFB": ("OFB", False, "algorithm.info.mode.ofb"),
    },
}


class AlgorithmInfoDialog(QDialog):
    def __init__(
        self,
        algorithm_name: str,
        algorithm: dict,
        selected_mode: str | None,
        lang,
        parent=None,
    ):
        super().__init__(parent)

        self.algorithm_name = algorithm_name
        self.algorithm = algorithm
        self.selected_mode = selected_mode
        self.lang = lang

        self.setWindowTitle(
            f"{self.lang.t('algorithm.info.title')} - {algorithm_name}"
        )
        self.resize(1000, 800)
        self.setMinimumSize(820, 560)

        layout = QVBoxLayout(self)

        info = ALGORITHM_INFO.get(algorithm_name, {})

        description = QLabel(
            self.lang.t(
                info.get(
                    "description",
                    "algorithm.info.description.default",
                )
            )
        )
        description.setWordWrap(True)
        description.setObjectName("algorithmInfoDescription")
        description.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Maximum,
        )
        layout.addWidget(description)
        layout.addSpacing(10)

        self.details_table = QTableWidget()
        details_table = self.details_table
        details_table.setObjectName("algorithmDetailsTable")
        details_table.setColumnCount(2)
        details_table.setHorizontalHeaderLabels([
            self.lang.t("algorithm.info.property"),
            self.lang.t("algorithm.info.value"),
        ])
        details_table.verticalHeader().setVisible(False)
        details_table.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        details_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        details_table.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection
        )
        details_table.setAlternatingRowColors(True)

        details_table.horizontalHeader().setSectionResizeMode(
            0,
            QHeaderView.ResizeMode.ResizeToContents,
        )
        details_table.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.Stretch,
        )

        details = self._build_algorithm_details(info)

        details_table.setRowCount(len(details))

        for row, (name, value) in enumerate(details):
            details_table.setItem(
                row,
                0,
                QTableWidgetItem(name),
            )
            details_table.setItem(
                row,
                1,
                QTableWidgetItem(value),
            )

        details_table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        details_table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        details_table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )

        layout.addWidget(details_table, 0)
        layout.addSpacing(10)

        self.modes_table = None
        modes = algorithm.get("modes", [])

        if modes:
            modes_label = QLabel(self.lang.t("algorithm.info.modes"))
            modes_label.setObjectName("algorithmInfoSectionTitle")
            layout.addWidget(modes_label)

            self.modes_table = self._create_modes_table(modes)
            layout.addWidget(self.modes_table, 1)
        else:
            layout.addStretch(1)

        close_button = AnimatedButton(self.lang.t("algorithm.info.close"))
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)
        QTimer.singleShot(0, self._update_table_sizes)

    def _build_algorithm_details(
        self,
        info: dict,
    ) -> list[tuple[str, str]]:
        algorithm_type = self.lang.t(
            "algorithm.info.type.symmetric"
            if self.algorithm.get("type") == "symmetric"
            else "algorithm.info.type.asymmetric"
        )

        standard = self.algorithm.get(
            "standard",
            self.lang.t("algorithm.info.unknown"),
        )
        family = self.algorithm.get("family")
        status = self.algorithm.get("status")

        key_lengths = self.algorithm.get(
            "key_lengths",
            [],
        )
        curves = self.algorithm.get(
            "curves",
            [],
        )
        hashes = self.algorithm.get(
            "hashes",
            [],
        )
        paddings = self.algorithm.get(
            "paddings",
            [],
        )
        parameter_sets = self.algorithm.get(
            "parameter_sets",
            [],
        )

        details = [
            (
                self.lang.t("algorithm.info.type"),
                algorithm_type,
            ),
            (
                self.lang.t("algorithm.info.primitive"),
                self.lang.t(
                    info.get(
                        "primitive",
                        "algorithm.info.unknown",
                    )
                ),
            ),
            (
                self.lang.t("algorithm.info.standard"),
                standard,
            ),
        ]

        if family:
            details.append((
                self.lang.t("algorithm.info.family"),
                self.lang.t(
                    f"algorithm.family.{family}"
                ),
            ))

        if status:
            details.append((
                self.lang.t("algorithm.info.status"),
                self.lang.t(
                    f"algorithm.status.{status}"
                ),
            ))

        details.extend([
            (
                self.lang.t("operations.group"),
                self.lang.t(
                    info.get(
                        "operations",
                        "algorithm.info.unknown",
                    )
                ),
            ),
            (
                self.lang.t("algorithm.info.streaming"),
                self._streaming_summary(),
            ),
        ])

        block_size = info.get("block_size")

        if block_size:
            details.append((
                self.lang.t("algorithm.info.block.size"),
                f"{block_size} bit",
            ))

        if key_lengths:
            details.append((
                self.lang.t("algorithm.info.key.lengths"),
                ", ".join(
                    str(length)
                    for length in key_lengths
                ),
            ))

        mode_key_lengths = self.algorithm.get(
            "mode_key_lengths",
            {},
        )

        for mode_name, lengths in mode_key_lengths.items():
            details.append((
                (
                    f"{self.lang.t('algorithm.info.key.lengths')} "
                    f"- {mode_name}"
                ),
                ", ".join(
                    str(length)
                    for length in lengths
                ),
            ))

        if parameter_sets:
            details.append((
                self.lang.t(
                    "algorithm.info.parameter.sets"
                ),
                ", ".join(parameter_sets),
            ))

        if curves:
            details.append((
                self.lang.t("algorithm.info.curves"),
                ", ".join(curves),
            ))

        if paddings:
            details.append((
                self.lang.t("algorithm.info.paddings"),
                ", ".join(paddings),
            ))

        if hashes:
            details.append((
                self.lang.t("algorithm.info.hashes"),
                ", ".join(hashes),
            ))

        return details

    def _streaming_summary(self) -> str:
        mode_streaming = self.algorithm.get(
            "mode_streaming"
        )

        if mode_streaming:
            values = list(mode_streaming.values())

            if all(values):
                return self.lang.t(
                    "algorithm.info.streaming.all"
                )

            if any(values):
                return self.lang.t(
                    "algorithm.info.streaming.some"
                )

            return self.lang.t(
                "no"
            )

        return self.lang.t(
            "yes"
            if self.algorithm.get("streaming", False)
            else "no"
        )

    def _create_modes_table(
        self,
        modes: list[str],
    ) -> QTableWidget:
        table = QTableWidget()
        table.setObjectName("algorithmInfoTable")
        table.setColumnCount(5)
        table.setItemDelegateForColumn(
            4,
            DescriptionDelegate(table),
        )

        table.setHorizontalHeaderLabels([
            self.lang.t("algorithm.mode"),
            self.lang.t("algorithm.info.mode.type"),
            self.lang.t("algorithm.info.streaming"),
            self.lang.t("algorithm.info.authentication"),
            self.lang.t("algorithm.info.description"),
        ])

        table.verticalHeader().setVisible(False)
        table.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        table.setAlternatingRowColors(True)
        table.setWordWrap(True)
        table.setTextElideMode(Qt.TextElideMode.ElideNone)
        table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        table.setRowCount(len(modes))

        mode_streaming = self.algorithm.get(
            "mode_streaming",
            {},
        )

        algorithm_modes = MODE_INFO.get(
            self.algorithm_name,
            {},
        )

        for row, mode_name in enumerate(modes):
            mode_type, authenticated, description_key = (
                algorithm_modes.get(
                    mode_name,
                    (
                        "—",
                        False,
                        "algorithm.info.description.default",
                    ),
                )
            )

            streaming = mode_streaming.get(
                mode_name,
                self.algorithm.get(
                    "streaming",
                    False,
                ),
            )

            values = [
                mode_name,
                mode_type,
                self.lang.t(
                    "yes"
                    if streaming
                    else "no"
                ),
                self.lang.t(
                    "yes"
                    if authenticated
                    else "no"
                ),
                self.lang.t(description_key),
            ]

            for column, value in enumerate(values):
                table.setItem(
                    row,
                    column,
                    QTableWidgetItem(value),
                )

            if mode_name == self.selected_mode:
                table.selectRow(row)

        header = table.horizontalHeader()

        header.setSectionResizeMode(
            0,
            QHeaderView.ResizeMode.ResizeToContents,
        )
        header.setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.ResizeToContents,
        )
        header.setSectionResizeMode(
            2,
            QHeaderView.ResizeMode.ResizeToContents,
        )
        header.setSectionResizeMode(
            3,
            QHeaderView.ResizeMode.ResizeToContents,
        )
        header.setSectionResizeMode(
            4,
            QHeaderView.ResizeMode.Stretch,
        )

        return table

    def _update_table_sizes(self):
        self.details_table.resizeRowsToContents()

        details_height = (
            self.details_table.horizontalHeader().height()
            + self.details_table.verticalHeader().length()
            + self.details_table.frameWidth() * 2
        )

        self.details_table.setFixedHeight(details_height)

        if self.modes_table is not None:
            self.modes_table.resizeRowsToContents()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        QTimer.singleShot(0, self._update_table_sizes)