from typing import Any, BinaryIO

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

from .base import CancelCallback, ProgressCallback, StreamCipher


BLOCK_SIZE = DES3.block_size
EAX_NONCE_SIZE = 16
EAX_TAG_SIZE = 8
CTR_NONCE_SIZE = 4


class DES3Stream(StreamCipher):
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
        mode_name = params.get("mode", "EAX (AEAD)")

        key = self._prepare_key(key)

        if mode_name == "EAX (AEAD)":
            self._encrypt_eax(
                fin,
                fout,
                key,
                should_cancel,
                report_progress,
                aad,
            )
            return

        if mode_name == "CTR":
            self._encrypt_ctr(
                fin,
                fout,
                key,
                should_cancel,
                report_progress,
            )
            return

        if mode_name == "CFB":
            self._encrypt_cfb(
                fin,
                fout,
                key,
                should_cancel,
                report_progress,
            )
            return

        if mode_name == "OFB":
            self._encrypt_ofb(
                fin,
                fout,
                key,
                should_cancel,
                report_progress,
            )
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
        mode_name = params.get("mode", "EAX (AEAD)")

        key = self._prepare_key(key)

        if mode_name == "EAX (AEAD)":
            self._decrypt_eax(
                fin,
                fout,
                key,
                should_cancel,
                report_progress,
                aad,
            )
            return

        if mode_name == "CTR":
            self._decrypt_ctr(
                fin,
                fout,
                key,
                should_cancel,
                report_progress,
            )
            return

        if mode_name == "CFB":
            self._decrypt_cfb(
                fin,
                fout,
                key,
                should_cancel,
                report_progress,
            )
            return

        if mode_name == "OFB":
            self._decrypt_ofb(
                fin,
                fout,
                key,
                should_cancel,
                report_progress,
            )
            return

        raise ValueError(self._message("operations.error.11", "Mode not supported."))

    def _encrypt_eax(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
        aad,
    ):
        nonce = get_random_bytes(EAX_NONCE_SIZE)
        cipher = DES3.new(
            key,
            DES3.MODE_EAX,
            nonce=nonce,
            mac_len=EAX_TAG_SIZE,
        )

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

    def _decrypt_eax(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
        aad,
    ):
        nonce = fin.read(EAX_NONCE_SIZE)

        if len(nonce) != EAX_NONCE_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        cipher = DES3.new(
            key,
            DES3.MODE_EAX,
            nonce=nonce,
            mac_len=EAX_TAG_SIZE,
        )

        if aad:
            cipher.update(aad)

        tail = b""

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            report_progress(len(chunk))
            data = tail + chunk

            if len(data) <= EAX_TAG_SIZE:
                tail = data
                continue

            ciphertext = data[:-EAX_TAG_SIZE]
            tail = data[-EAX_TAG_SIZE:]

            fout.write(cipher.decrypt(ciphertext))

        if len(tail) != EAX_TAG_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        try:
            cipher.verify(tail)
        except ValueError as exc:
            raise ValueError(self._message("operations.error.2", "Authentication failed.")) from exc

    def _encrypt_ctr(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        nonce = get_random_bytes(CTR_NONCE_SIZE)
        cipher = DES3.new(
            key,
            DES3.MODE_CTR,
            nonce=nonce,
        )

        fout.write(nonce)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.encrypt(chunk))
            report_progress(len(chunk))

    def _decrypt_ctr(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        nonce = fin.read(CTR_NONCE_SIZE)

        if len(nonce) != CTR_NONCE_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        cipher = DES3.new(
            key,
            DES3.MODE_CTR,
            nonce=nonce,
        )

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.decrypt(chunk))
            report_progress(len(chunk))

    def _encrypt_cfb(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = DES3.new(
            key,
            DES3.MODE_CFB,
            iv=iv,
            segment_size=64,
        )

        fout.write(iv)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.encrypt(chunk))
            report_progress(len(chunk))

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

        cipher = DES3.new(
            key,
            DES3.MODE_CFB,
            iv=iv,
            segment_size=64,
        )

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.decrypt(chunk))
            report_progress(len(chunk))

    def _encrypt_ofb(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = DES3.new(
            key,
            DES3.MODE_OFB,
            iv=iv,
        )

        fout.write(iv)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.encrypt(chunk))
            report_progress(len(chunk))

    def _decrypt_ofb(
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

        cipher = DES3.new(
            key,
            DES3.MODE_OFB,
            iv=iv,
        )

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.decrypt(chunk))
            report_progress(len(chunk))

    def _prepare_key(self, key: bytes) -> bytes:
        key_length = len(key) * 8

        if key_length != 192:
            raise ValueError(
                self._message(
                    "key.error.6",
                    "Invalid key length for the $ algorithm. Expected: #. Selected: @.",
                )
                .replace("$", "3DES")
                .replace("#", "192 bits")
                .replace("@", f"{key_length} bits")
            )

        try:
            return DES3.adjust_key_parity(key)
        except ValueError as exc:
            raise ValueError(self._message("key.error.11", "Invalid 3DES key.")) from exc

    @staticmethod
    def _check_cancelled(should_cancel):
        if should_cancel():
            raise RuntimeError("CANCELLED")

    def _message(self, key, fallback):
        if self.lang:
            return self.lang.t(key)

        return fallback