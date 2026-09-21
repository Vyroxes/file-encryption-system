import tempfile
from typing import Any, BinaryIO

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

from .base import CancelCallback, ProgressCallback, StreamCipher


KEY_SIZE = 32
TAG_SIZE = 16
SPOOL_SIZE = 8 * 1024 * 1024


class _ChaCha20Poly1305Stream(StreamCipher):
    algorithm_name = ""
    nonce_size = 0

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

        nonce = get_random_bytes(self.nonce_size)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

        if aad:
            cipher.update(aad)

        fout.write(nonce)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.encrypt(chunk))
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)
        fout.write(cipher.digest())

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

        nonce = fin.read(self.nonce_size)

        if len(nonce) != self.nonce_size:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

        if aad:
            cipher.update(aad)

        with tempfile.SpooledTemporaryFile(max_size=SPOOL_SIZE) as plaintext:
            tail = b""

            while True:
                self._check_cancelled(should_cancel)

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                report_progress(len(chunk))
                data = tail + chunk

                if len(data) <= TAG_SIZE:
                    tail = data
                    continue

                ciphertext = data[:-TAG_SIZE]
                tail = data[-TAG_SIZE:]

                plaintext.write(cipher.decrypt(ciphertext))

            if len(tail) != TAG_SIZE:
                raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

            self._check_cancelled(should_cancel)

            try:
                cipher.verify(tail)
            except ValueError as exc:
                raise ValueError(self._message("operations.error.2", "Authentication failed.")) from exc

            plaintext.seek(0)

            while True:
                self._check_cancelled(should_cancel)

                chunk = plaintext.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(chunk)

    def _validate_key(self, key: bytes):
        key_length = len(key) * 8

        if len(key) != KEY_SIZE:
            raise ValueError(
                self._message(
                    "key.error.6",
                    "Invalid key length for the $ algorithm. Expected: #. Selected: @.",
                )
                .replace("$", self.algorithm_name)
                .replace("#", "256 bits")
                .replace("@", f"{key_length} bits")
            )

    @staticmethod
    def _check_cancelled(should_cancel):
        if should_cancel():
            raise RuntimeError("CANCELLED")

    def _message(self, key, fallback):
        if self.lang:
            return self.lang.t(key)

        return fallback


class ChaCha20Poly1305Stream(_ChaCha20Poly1305Stream):
    algorithm_name = "ChaCha20-Poly1305"
    nonce_size = 12


class XChaCha20Poly1305Stream(_ChaCha20Poly1305Stream):
    algorithm_name = "XChaCha20-Poly1305"
    nonce_size = 24