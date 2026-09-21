from PySide6.QtCore import QThread, Signal

from key_manager import generate_key


class KeyGenerationWorker(QThread):
    generated = Signal(str, str, bool)
    failed = Signal(str, str, bool)

    def __init__(
        self,
        key_type: str,
        public: bool,
        private_key_path: str,
        algorithm_name: str,
        key_length_bits: int | None,
        output_path: str,
        mode: str | None = None,
        curve: str | None = None,
        lang=None,
    ):
        super().__init__()

        self.key_type = key_type
        self.public = public
        self.private_key_path = private_key_path
        self.algorithm_name = algorithm_name
        self.key_length_bits = key_length_bits
        self.output_path = output_path
        self.mode = mode
        self.curve = curve
        self.lang = lang

    def run(self):
        try:
            generated_path = generate_key(
                key_type=self.key_type,
                public=self.public,
                private_key_path=self.private_key_path,
                algorithm_name=self.algorithm_name,
                key_length_bits=self.key_length_bits,
                output_path=self.output_path,
                mode=self.mode,
                lang=self.lang,
                curve=self.curve,
            )

            self.generated.emit(
                generated_path,
                self.key_type,
                self.public,
            )

        except Exception as exc:
            self.failed.emit(
                str(exc),
                self.key_type,
                self.public,
            )