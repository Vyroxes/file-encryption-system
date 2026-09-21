from os import urandom
from typing import Any, BinaryIO

from xycrypto.ciphers import Camellia_CBC, Camellia_CFB

from .base import CancelCallback, ProgressCallback, StreamCipher


BLOCK_SIZE = 16
VALID_KEY_LENGTHS = (128, 192, 256)


class CamelliaStream(StreamCipher):
    chunk_size = 64 * 1024

    def __init__(self, lang=None):
        self.lang = lang

    def encrypt_stream(
        self,
        fin: BinaryIO,
        fout: BinaryIO,
        key: bytes,
        params: dict[str, Any] | None = None,
        should_cancel: CancelCallback = lambda: False,
        report_progress: ProgressCallback = lambda _: None,
        aad: bytes = b"",
    ) -> None:
        params = params or {}
        mode_name = params.get("mode", "CFB")

        self._validate_key(key)

        if mode_name == "CFB":
            self._encrypt_cfb(fin, fout, key, should_cancel, report_progress)
            return

        if mode_name == "CBC":
            self._encrypt_cbc(fin, fout, key, should_cancel, report_progress)
            return

        raise ValueError(self._message("operations.error.11", "Mode not supported."))

    def decrypt_stream(
        self,
        fin: BinaryIO,
        fout: BinaryIO,
        key: bytes,
        params: dict[str, Any] | None = None,
        should_cancel: CancelCallback = lambda: False,
        report_progress: ProgressCallback = lambda _: None,
        aad: bytes = b"",
    ) -> None:
        params = params or {}
        mode_name = params.get("mode", "CFB")

        self._validate_key(key)

        if mode_name == "CFB":
            self._decrypt_cfb(fin, fout, key, should_cancel, report_progress)
            return

        if mode_name == "CBC":
            self._decrypt_cbc(fin, fout, key, should_cancel, report_progress)
            return

        raise ValueError(self._message("operations.error.11", "Mode not supported."))

    def _encrypt_cfb(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        iv = urandom(BLOCK_SIZE)
        cipher = Camellia_CFB(key, iv=iv)
        encryptor = cipher.encryptor()

        fout.write(iv)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(encryptor.update(chunk))
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)
        fout.write(encryptor.finalize())

    def _decrypt_cfb(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        iv = fin.read(BLOCK_SIZE)

        if len(iv) != BLOCK_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        cipher = Camellia_CFB(key, iv=iv)
        decryptor = cipher.decryptor()

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(decryptor.update(chunk))
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)
        fout.write(decryptor.finalize())

    def _encrypt_cbc(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        iv = urandom(BLOCK_SIZE)
        cipher = Camellia_CBC(key, iv=iv, padding="PKCS7")
        encryptor = cipher.encryptor()

        fout.write(iv)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(encryptor.update(chunk))
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)
        fout.write(encryptor.finalize())

    def _decrypt_cbc(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        iv = fin.read(BLOCK_SIZE)

        if len(iv) != BLOCK_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        cipher = Camellia_CBC(key, iv=iv, padding="PKCS7")
        decryptor = cipher.decryptor()

        try:
            while True:
                self._check_cancelled(should_cancel)

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(decryptor.update(chunk))
                report_progress(len(chunk))

            self._check_cancelled(should_cancel)
            fout.write(decryptor.finalize())
        except ValueError as exc:
            raise ValueError(self._message("operations.error.14", "Decryption failed. The key may be incorrect or the encrypted data may be corrupted.")) from exc

    def _validate_key(self, key: bytes):
        key_length = len(key) * 8

        if key_length not in VALID_KEY_LENGTHS:
            expected = ", ".join(str(length) for length in VALID_KEY_LENGTHS)
            raise ValueError(self._message("key.error.6", "Invalid key length for the $ algorithm. Expected: #. Selected: @.").replace("$", "Camellia").replace("#", f"{expected} bits").replace("@", f"{key_length} bits"))

    @staticmethod
    def _check_cancelled(should_cancel):
        if should_cancel():
            raise RuntimeError("CANCELLED")

    def _message(self, key, fallback):
        if self.lang:
            return self.lang.t(key)

        return fallback