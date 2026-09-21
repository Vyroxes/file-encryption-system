import os
import tempfile

from PySide6.QtCore import QThread, Signal

from algorithms import ALGORITHMS, StreamCipher, Signer
from password_kdf import create_kdf_params, derive_password_key
from file_format import read_header, write_header


class CryptoWorker(QThread):
    progress = Signal(int)
    finished = Signal(str)
    verification_finished = Signal(bool)
    error = Signal(str)

    def __init__(
        self,
        operation: str,
        algorithm_name: str,
        input_file: str,
        output_file: str,
        key_path: str = None,
        private_key_path: str = None,
        public_key_path: str = None,
        signature_path: str | None = None,
        password: str | None = None,
        kdf_name: str | None = None,
        params: dict | None = None,
        lang=None,
    ):
        super().__init__()

        self._cancelled = False

        self.operation = operation
        self.algorithm_name = algorithm_name
        self.input_file = input_file
        self.output_file = output_file

        self.key_path = key_path
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.signature_path = signature_path
        self.password = password
        self.kdf_name = kdf_name
        self.params = params or {}
        self.lang = lang

        self._temp_output_path = None

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            if self._cancelled:
                return

            algorithm = self._load_algorithm(
                self.algorithm_name
            )

            if self.operation == "encrypt":
                self._encrypt(algorithm)

            elif self.operation == "decrypt":
                self._decrypt()

            elif self.operation == "sign":
                self._sign(algorithm)

            elif self.operation == "verify":
                valid = self._verify(algorithm)

                if not self._cancelled:
                    self.progress.emit(100)
                    self.verification_finished.emit(
                        valid
                    )

                return

            else:
                raise ValueError(
                    self.lang.t(
                        "operations.error.10"
                    )
                )

            if not self._cancelled:
                self.progress.emit(100)
                self.finished.emit(
                    self.output_file or ""
                )

        except RuntimeError as exc:
            if str(exc) != "CANCELLED":
                self.error.emit(str(exc))

        except Exception as exc:
            self.error.emit(str(exc))

        finally:
            self._remove_temp_output()

    def _encrypt(self, algorithm):
        total_size = os.path.getsize(self.input_file)
        processed = 0

        def report_progress(processed_bytes: int):
            nonlocal processed
            processed += processed_bytes

            if total_size == 0:
                percent = 99
            else:
                percent = int(processed * 100 / total_size)

            self.progress.emit(min(percent, 99))

        with open(self.input_file, "rb") as fin:
            fout = self._create_temp_output()

            with fout:
                if not isinstance(algorithm, StreamCipher):
                    raise ValueError(self._message("operations.error.10", "Operation not supported"))

                params = dict(self.params)

                key = self._get_encryption_key(
                    params
                )

                header_bytes = write_header(
                    fout,
                    {
                        "algorithm": self.algorithm_name,
                        "params": params,
                    },
                )

                algorithm.encrypt_stream(
                    fin,
                    fout,
                    key,
                    params,
                    lambda: self._cancelled,
                    report_progress,
                    aad=header_bytes,
                )

                if self._cancelled:
                    raise RuntimeError("CANCELLED")

                fout.flush()
                os.fsync(fout.fileno())

        self._commit_temp_output()

    def _decrypt(self):
        total_size = os.path.getsize(self.input_file)
        processed = 0

        def report_progress(processed_bytes: int):
            nonlocal processed
            processed += processed_bytes

            if total_size == 0:
                percent = 99
            else:
                percent = int(processed * 100 / total_size)

            self.progress.emit(min(percent, 99))

        with open(self.input_file, "rb") as fin:
            fout = self._create_temp_output()

            with fout:
                header, header_bytes = read_header(fin, lang=self.lang)

                self._validate_decryption_settings(header)

                algorithm_name = header["algorithm"]
                algorithm = self._load_algorithm(algorithm_name)

                if not isinstance(algorithm, StreamCipher):
                    raise ValueError(self._message("operations.error.10", "Operation not supported."))

                key = self._get_decryption_key(header["params"], algorithm_name)

                algorithm.decrypt_stream(
                    fin,
                    fout,
                    key,
                    header["params"],
                    lambda: self._cancelled,
                    report_progress,
                    aad=header_bytes,
                )

                if self._cancelled:
                    raise RuntimeError("CANCELLED")

                fout.flush()
                os.fsync(fout.fileno())

        self._commit_temp_output()

    def _get_encryption_key(
        self,
        params: dict,
    ) -> bytes:
        if self.password is None:
            params["key_source"] = "key_file"
            params.pop("kdf", None)

            return self._load_key(
                self.key_path
            )

        key_length = params.get(
            "key_length"
        )

        if not key_length:
            raise ValueError(
                self._message(
                    "password.error.key.length",
                    "Key length is required for password-based encryption.",
                )
            )

        kdf_params = create_kdf_params(
            self.kdf_name or "argon2id"
        )

        params["key_source"] = "password"
        params["kdf"] = kdf_params

        return derive_password_key(
            self.password,
            int(key_length),
            kdf_params,
            self.algorithm_name,
        )


    def _get_decryption_key(
        self,
        params: dict,
        algorithm_name: str,
    ) -> bytes:
        key_source = params.get(
            "key_source",
            "key_file",
        )

        if key_source == "key_file":
            return self._load_key(
                self.key_path
            )

        if key_source != "password":
            raise ValueError(
                self._message(
                    "password.error.source",
                    "Unsupported key source.",
                )
            )

        if not self.password:
            raise ValueError(
                self._message(
                    "password.error.empty",
                    "Please enter the password.",
                )
            )

        kdf_params = params.get("kdf")

        if not isinstance(kdf_params, dict):
            raise ValueError(
                self._message(
                    "password.error.kdf",
                    "Invalid KDF parameters.",
                )
            )

        key_length = params.get(
            "key_length"
        )

        if not key_length:
            raise ValueError(
                self._message(
                    "password.error.key.length",
                    "Key length is required for password-based encryption.",
                )
            )

        return derive_password_key(
            self.password,
            int(key_length),
            kdf_params,
            algorithm_name,
        )

    def _sign(self, algo):
        if not isinstance(algo, Signer):
            raise ValueError(self.lang.t("operations.error.10"))

        total_size = os.path.getsize(self.input_file)
        processed = 0

        def report_progress(read_bytes: int):
            nonlocal processed

            processed += read_bytes

            if total_size > 0:
                percent = int(processed * 100 / total_size)
                self.progress.emit(min(percent, 99))

        private_key = self._load_key(
            self.private_key_path,
            "key.error.2",
        )

        with open(self.input_file, "rb") as fin:
            signature = algo.sign_stream(
                fin,
                private_key,
                self.params,
                lambda: self._cancelled,
                report_progress,
            )

        if self._cancelled:
            raise RuntimeError("CANCELLED")

        self._atomic_write_bytes(
            self.output_file,
            signature,
        )

    def _verify(self, algo) -> bool:
        if not isinstance(algo, Signer):
            raise ValueError(self.lang.t("operations.error.10"))

        total_size = os.path.getsize(self.input_file)
        processed = 0

        def report_progress(read_bytes: int):
            nonlocal processed

            processed += read_bytes

            if total_size > 0:
                percent = int(processed * 100 / total_size)
                self.progress.emit(min(percent, 99))

        public_key = self._load_key(
            self.public_key_path,
            "key.error.3",
        )

        signature = self._load_signature()

        with open(self.input_file, "rb") as fin:
            return algo.verify_stream(
                fin,
                public_key,
                signature,
                self.params,
                lambda: self._cancelled,
                report_progress,
            )

    def _load_signature(self) -> bytes:
        if not self.signature_path or not os.path.exists(self.signature_path):
            raise FileNotFoundError(self.lang.t("signature.error"))

        with open(self.signature_path, "rb") as file:
            signature = file.read()

        if not signature:
            raise ValueError(self.lang.t("signature.error.2"))

        return signature

    def _validate_decryption_settings(self, header):
        header_algorithm = header["algorithm"]

        if self.algorithm_name != header_algorithm:
            message = self._message("operations.error.12", "Selected algorithm does not match the encrypted file metadata. Expected: $. Selected: #.")
            raise ValueError(message.replace("$", header_algorithm).replace("#", self.algorithm_name))

        header_params = header["params"]

        parameter_labels = {
            "mode": "algorithm.mode",
            "key_length": "algorithm.key.length",
            "hash": "algorithm.hash",
            "padding": "algorithm.padding",
            "curve": "algorithm.curve",
        }

        for parameter, translation_key in parameter_labels.items():
            expected = header_params.get(parameter)

            if expected is None:
                continue

            selected = self.params.get(parameter)

            if selected != expected:
                label = self._message(translation_key, parameter)
                message = self._message("operations.error.13","Selected algorithm setting '$' does not match the encrypted file metadata. Expected: #. Selected: @.")
                raise ValueError(message.replace("$", label).replace("#", str(expected)).replace("@", str(selected)))

    def _load_algorithm(self, algorithm_name):
        config = ALGORITHMS.get(algorithm_name)

        if not config:
            raise ValueError(self._message("operations.error.9", "Unknown algorithm"))

        implementation = config.get("implementation")

        if implementation is None:
            raise ValueError(self._message("operations.error.9", "Algorithm is not implemented yet"))

        return implementation(lang=self.lang)

    def _load_key(self, path: str, error_key: str = "key.error") -> bytes:
        if not path or not os.path.exists(path):
            raise FileNotFoundError(self.lang.t(error_key))

        with open(path, "rb") as file:
            return file.read()

    def _message(self, key, fallback):
        if self.lang:
            return self.lang.t(key)

        return fallback

    def _create_temp_output(self):
        output_directory = os.path.dirname(os.path.abspath(self.output_file)) or "."

        fd, temp_path = tempfile.mkstemp(
            prefix=".crypto_",
            suffix=".tmp",
            dir=output_directory,
        )

        self._temp_output_path = temp_path

        return os.fdopen(fd, "wb")

    def _commit_temp_output(self):
        if self._cancelled:
            raise RuntimeError("CANCELLED")

        if not self._temp_output_path:
            raise RuntimeError("Temporary output file does not exist")

        os.replace(self._temp_output_path, self.output_file)
        self._temp_output_path = None

    def _remove_temp_output(self):
        if not self._temp_output_path:
            return

        try:
            if os.path.exists(self._temp_output_path):
                os.remove(self._temp_output_path)
        except OSError:
            pass
        finally:
            self._temp_output_path = None

    @staticmethod
    def _atomic_write_bytes(output_path: str, data: bytes) -> None:
        directory = os.path.dirname(os.path.abspath(output_path)) or "."

        fd, temp_path = tempfile.mkstemp(
            prefix=".signature_",
            suffix=".tmp",
            dir=directory,
        )

        try:
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())

            os.replace(temp_path, output_path)

        except Exception:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            finally:
                raise