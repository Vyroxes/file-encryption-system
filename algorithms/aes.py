from tempfile import SpooledTemporaryFile
from typing import Any, BinaryIO

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .base import CancelCallback, ProgressCallback, StreamCipher


BLOCK_SIZE = AES.block_size
TAG_SIZE = 16


class AESStream(StreamCipher):
    AEAD_MODES = ("GCM (AEAD)", "EAX (AEAD)")
    NON_STREAM_AEAD_MODES = ("SIV (AEAD)", "CCM (AEAD)", "OCB (AEAD)")

    spool_size = 8 * 1024 * 1024

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
        mode_name = params.get("mode", "GCM (AEAD)")

        self._validate_key(key, mode_name)

        if mode_name in self.NON_STREAM_AEAD_MODES:
            self._encrypt_non_stream_aead(
                fin,
                fout,
                key,
                mode_name,
                should_cancel,
                report_progress,
                aad,
            )
            return

        if mode_name in self.AEAD_MODES:
            self._encrypt_aead(
                fin,
                fout,
                key,
                mode_name,
                should_cancel,
                report_progress,
                aad,
            )
            return

        if mode_name in ("CBC", "ECB"):
            self._encrypt_block_mode(
                fin,
                fout,
                key,
                mode_name,
                should_cancel,
                report_progress,
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

        raise ValueError(self._message("operations.error.11", "Unsupported AES mode"))

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
        mode_name = params.get("mode", "GCM (AEAD)")

        self._validate_key(key, mode_name)

        if mode_name in self.NON_STREAM_AEAD_MODES:
            self._decrypt_non_stream_aead(
                fin,
                fout,
                key,
                mode_name,
                should_cancel,
                report_progress,
                aad,
            )
            return

        if mode_name in self.AEAD_MODES:
            self._decrypt_aead(
                fin,
                fout,
                key,
                mode_name,
                should_cancel,
                report_progress,
                aad,
            )
            return

        if mode_name in ("CBC", "ECB"):
            self._decrypt_block_mode(
                fin,
                fout,
                key,
                mode_name,
                should_cancel,
                report_progress,
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

        raise ValueError(self._message("operations.error.11", "Unsupported AES mode"))

    def _encrypt_aead(
        self,
        fin,
        fout,
        key,
        mode_name,
        should_cancel,
        report_progress,
        aad,
    ):
        nonce = get_random_bytes(12)

        mode = AES.MODE_GCM if mode_name == "GCM (AEAD)" else AES.MODE_EAX
        cipher = AES.new(key, mode, nonce=nonce)

        self._apply_aad(cipher, aad)

        fout.write(nonce)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.encrypt(chunk))
            report_progress(len(chunk))

        fout.write(cipher.digest())

    def _decrypt_aead(
        self,
        fin,
        fout,
        key,
        mode_name,
        should_cancel,
        report_progress,
        aad,
    ):
        nonce = fin.read(12)

        if len(nonce) != 12:
            raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

        mode = AES.MODE_GCM if mode_name == "GCM (AEAD)" else AES.MODE_EAX
        cipher = AES.new(key, mode, nonce=nonce)

        self._apply_aad(cipher, aad)

        tail = b""

        with SpooledTemporaryFile(max_size=self.spool_size, mode="w+b") as plaintext_file:
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

                plaintext_file.write(cipher.decrypt(ciphertext))

            if len(tail) != TAG_SIZE:
                raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

            try:
                cipher.verify(tail)
            except ValueError as exc:
                raise ValueError(self._message("operations.error.2", "Authentication failed")) from exc

            plaintext_file.seek(0)

            while True:
                self._check_cancelled(should_cancel)

                chunk = plaintext_file.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(chunk)

    def _encrypt_block_mode(
        self,
        fin,
        fout,
        key,
        mode_name,
        should_cancel,
        report_progress,
    ):
        if mode_name == "CBC":
            iv = get_random_bytes(BLOCK_SIZE)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            fout.write(iv)
        else:
            cipher = AES.new(key, AES.MODE_ECB)

        buffer = b""

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            report_progress(len(chunk))
            buffer += chunk

            process_length = len(buffer) - BLOCK_SIZE
            process_length -= process_length % BLOCK_SIZE

            if process_length > 0:
                fout.write(cipher.encrypt(buffer[:process_length]))
                buffer = buffer[process_length:]

        fout.write(cipher.encrypt(pad(buffer, BLOCK_SIZE)))

    def _decrypt_block_mode(
        self,
        fin,
        fout,
        key,
        mode_name,
        should_cancel,
        report_progress,
    ):
        if mode_name == "CBC":
            iv = fin.read(BLOCK_SIZE)

            if len(iv) != BLOCK_SIZE:
                raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        else:
            cipher = AES.new(key, AES.MODE_ECB)

        buffer = b""

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            report_progress(len(chunk))
            buffer += chunk

            process_length = len(buffer) - BLOCK_SIZE
            process_length -= process_length % BLOCK_SIZE

            if process_length > 0:
                fout.write(cipher.decrypt(buffer[:process_length]))
                buffer = buffer[process_length:]

        if len(buffer) != BLOCK_SIZE:
            raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

        try:
            fout.write(unpad(cipher.decrypt(buffer), BLOCK_SIZE))
        except ValueError as exc:
            raise ValueError(self._message("operations.error.2", "Invalid padding or key")) from exc

    def _encrypt_ctr(
        self,
        fin,
        fout,
        key,
        should_cancel,
        report_progress,
    ):
        nonce = get_random_bytes(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

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
        nonce = fin.read(8)

        if len(nonce) != 8:
            raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(cipher.decrypt(chunk))
            report_progress(len(chunk))

    def _encrypt_non_stream_aead(
        self,
        fin,
        fout,
        key,
        mode_name,
        should_cancel,
        report_progress,
        aad,
    ):
        self._check_cancelled(should_cancel)

        data = fin.read()
        report_progress(len(data))

        if mode_name == "SIV (AEAD)":
            cipher = AES.new(key, AES.MODE_SIV)
            self._apply_aad(cipher, aad)

            ciphertext, tag = cipher.encrypt_and_digest(data)

            fout.write(ciphertext)
            fout.write(tag)
            return

        if mode_name == "CCM (AEAD)":
            nonce = get_random_bytes(11)
            cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
            self._apply_aad(cipher, aad)

            ciphertext, tag = cipher.encrypt_and_digest(data)

            fout.write(nonce)
            fout.write(ciphertext)
            fout.write(tag)
            return

        if mode_name == "OCB (AEAD)":
            nonce = get_random_bytes(15)
            cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
            self._apply_aad(cipher, aad)

            ciphertext, tag = cipher.encrypt_and_digest(data)

            fout.write(nonce)
            fout.write(ciphertext)
            fout.write(tag)
            return

        raise ValueError(self._message("operations.error.11", "Unsupported AES mode"))

    def _decrypt_non_stream_aead(
        self,
        fin,
        fout,
        key,
        mode_name,
        should_cancel,
        report_progress,
        aad,
    ):
        self._check_cancelled(should_cancel)

        data = fin.read()
        report_progress(len(data))

        try:
            if mode_name == "SIV (AEAD)":
                if len(data) < TAG_SIZE:
                    raise ValueError

                ciphertext = data[:-TAG_SIZE]
                tag = data[-TAG_SIZE:]

                cipher = AES.new(key, AES.MODE_SIV)
                self._apply_aad(cipher, aad)

                fout.write(cipher.decrypt_and_verify(ciphertext, tag))
                return

            if mode_name == "CCM (AEAD)":
                if len(data) < 11 + TAG_SIZE:
                    raise ValueError

                nonce = data[:11]
                ciphertext = data[11:-TAG_SIZE]
                tag = data[-TAG_SIZE:]

                cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
                self._apply_aad(cipher, aad)

                fout.write(cipher.decrypt_and_verify(ciphertext, tag))
                return

            if mode_name == "OCB (AEAD)":
                if len(data) < 15 + TAG_SIZE:
                    raise ValueError

                nonce = data[:15]
                ciphertext = data[15:-TAG_SIZE]
                tag = data[-TAG_SIZE:]

                cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
                self._apply_aad(cipher, aad)

                fout.write(cipher.decrypt_and_verify(ciphertext, tag))
                return

            raise ValueError(self._message("operations.error.11", "Unsupported AES mode"))

        except ValueError as exc:
            raise ValueError(self._message("operations.error.2", "Authentication failed")) from exc

    def _validate_key(self, key: bytes, mode_name: str):
        if mode_name == "SIV (AEAD)":
            valid_lengths = (256, 384, 512)
        else:
            valid_lengths = (128, 192, 256)

        key_length = len(key) * 8

        if key_length not in valid_lengths:
            expected = ", ".join(str(length) for length in valid_lengths)
            message = self._message("key.error.6", "Invalid key length for the $ algorithm. Expected: #. Selected: @.")
            raise ValueError(message.replace("$", f"AES-{mode_name}").replace("#", f"{expected} bits").replace("@", f"{key_length} bits"))

    @staticmethod
    def _apply_aad(cipher, aad: bytes):
        if aad:
            cipher.update(aad)

    @staticmethod
    def _check_cancelled(should_cancel):
        if should_cancel():
            raise RuntimeError("CANCELLED")

    def _message(self, key, fallback):
        if self.lang:
            return self.lang.t(key)

        return fallback