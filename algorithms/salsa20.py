from typing import Any, BinaryIO

from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

from .base import CancelCallback, ProgressCallback, StreamCipher


KEY_SIZE = 32
NONCE_SIZE = 8


class Salsa20Stream(StreamCipher):
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
        self._validate_key(key)

        nonce = get_random_bytes(NONCE_SIZE)
        cipher = Salsa20.new(key=key, nonce=nonce)

        fout.write(nonce)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.encrypt(chunk))
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)

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
        self._validate_key(key)

        nonce = fin.read(NONCE_SIZE)

        if len(nonce) != NONCE_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        cipher = Salsa20.new(key=key, nonce=nonce)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.decrypt(chunk))
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)

    def _validate_key(self, key: bytes):
        key_length = len(key) * 8

        if len(key) != KEY_SIZE:
            message = self._message("key.error.6", "Invalid key length for the $ algorithm. Expected: #. Selected: @.")
            raise ValueError(message.replace("$", "Salsa20").replace("#", "256 bits").replace("@", f"{key_length} bits"))

    @staticmethod
    def _check_cancelled(should_cancel):
        if should_cancel():
            raise RuntimeError("CANCELLED")

    def _message(self, key, fallback):
        if self.lang:
            return self.lang.t(key)

        return fallback