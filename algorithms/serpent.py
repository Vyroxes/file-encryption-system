from tempfile import SpooledTemporaryFile
from typing import Any, BinaryIO

from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from pyserpent import Serpent

from .base import CancelCallback, ProgressCallback, StreamCipher


BLOCK_SIZE = 16
SALT_SIZE = 16
IV_SIZE = 16
TAG_SIZE = 32
MODE_NAME = "CBC + HMAC-SHA256"

ENC_CONTEXT = b"file-encryption-system/serpent-cbc/enc/v1"
MAC_CONTEXT = b"file-encryption-system/serpent-cbc/mac/v1"
MAC_DOMAIN = b"file-encryption-system/serpent-cbc-hmac/v1"


class SerpentStream(StreamCipher):
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
        mode_name = params.get("mode") or MODE_NAME

        self._validate_mode(mode_name)
        self._validate_key(key)

        salt = get_random_bytes(SALT_SIZE)
        iv = get_random_bytes(IV_SIZE)

        encryption_key, mac_key = self._derive_keys(key, salt)

        cipher = Serpent(encryption_key)
        mac = self._create_mac(mac_key, aad, salt, iv)

        fout.write(salt)
        fout.write(iv)

        previous_block = iv
        buffer = b""

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            report_progress(len(chunk))
            buffer += chunk

            process_length = len(buffer) - (len(buffer) % BLOCK_SIZE)

            for offset in range(0, process_length, BLOCK_SIZE):
                block = buffer[offset:offset + BLOCK_SIZE]
                encrypted_block = cipher.encrypt(
                    self._xor_blocks(block, previous_block)
                )

                fout.write(encrypted_block)
                mac.update(encrypted_block)

                previous_block = encrypted_block

            buffer = buffer[process_length:]

        padding_length = BLOCK_SIZE - len(buffer)
        final_block = buffer + bytes([padding_length]) * padding_length

        encrypted_block = cipher.encrypt(
            self._xor_blocks(final_block, previous_block)
        )

        fout.write(encrypted_block)
        mac.update(encrypted_block)
        fout.write(mac.digest())

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
        mode_name = params.get("mode") or MODE_NAME

        self._validate_mode(mode_name)
        self._validate_key(key)

        salt = fin.read(SALT_SIZE)
        iv = fin.read(IV_SIZE)

        if len(salt) != SALT_SIZE or len(iv) != IV_SIZE:
            raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

        encryption_key, mac_key = self._derive_keys(key, salt)

        cipher = Serpent(encryption_key)
        mac = self._create_mac(mac_key, aad, salt, iv)

        buffer = b""
        previous_block = iv
        last_plaintext_block = None

        with SpooledTemporaryFile(max_size=self.spool_size, mode="w+b") as plaintext_file:
            while True:
                self._check_cancelled(should_cancel)

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                report_progress(len(chunk))
                buffer += chunk

                process_length = max(0, len(buffer) - TAG_SIZE)
                process_length -= process_length % BLOCK_SIZE

                for offset in range(0, process_length, BLOCK_SIZE):
                    ciphertext_block = buffer[offset:offset + BLOCK_SIZE]

                    mac.update(ciphertext_block)

                    decrypted_block = self._xor_blocks(
                        cipher.decrypt(ciphertext_block),
                        previous_block,
                    )

                    if last_plaintext_block is not None:
                        plaintext_file.write(last_plaintext_block)

                    last_plaintext_block = decrypted_block
                    previous_block = ciphertext_block

                buffer = buffer[process_length:]

            if len(buffer) != TAG_SIZE or last_plaintext_block is None:
                raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

            tag = buffer

            try:
                mac.verify(tag)
            except ValueError as exc:
                raise ValueError(self._message("operations.error.2", "Authentication failed")) from exc

            final_block = self._unpad_block(last_plaintext_block)
            plaintext_file.write(final_block)
            plaintext_file.seek(0)

            while True:
                self._check_cancelled(should_cancel)

                chunk = plaintext_file.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(chunk)

    @staticmethod
    def _derive_keys(
        key: bytes,
        salt: bytes,
    ) -> tuple[bytes, bytes]:
        encryption_key = HKDF(
            key,
            len(key),
            salt,
            SHA256,
            context=ENC_CONTEXT,
        )

        mac_key = HKDF(
            key,
            TAG_SIZE,
            salt,
            SHA256,
            context=MAC_CONTEXT,
        )

        return encryption_key, mac_key

    @staticmethod
    def _create_mac(
        mac_key: bytes,
        aad: bytes,
        salt: bytes,
        iv: bytes,
    ):
        mac = HMAC.new(mac_key, digestmod=SHA256)

        mac.update(MAC_DOMAIN)
        mac.update(len(aad).to_bytes(8, "big"))
        mac.update(aad)
        mac.update(salt)
        mac.update(iv)

        return mac

    @staticmethod
    def _xor_blocks(
        first: bytes,
        second: bytes,
    ) -> bytes:
        return bytes(a ^ b for a, b in zip(first, second))

    def _unpad_block(self, block: bytes) -> bytes:
        padding_length = block[-1]

        if padding_length < 1 or padding_length > BLOCK_SIZE:
            raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

        if block[-padding_length:] != bytes([padding_length]) * padding_length:
            raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

        return block[:-padding_length]

    def _validate_mode(self, mode_name: str) -> None:
        if mode_name != MODE_NAME:
            raise ValueError(self._message("operations.error.11", "Unsupported Serpent mode"))

    def _validate_key(self, key: bytes) -> None:
        key_length = len(key) * 8
        valid_lengths = (128, 192, 256)

        if key_length not in valid_lengths:
            expected = ", ".join(str(length) for length in valid_lengths)
            message = self._message(
                "key.error.6",
                "Invalid key length for the $ algorithm. Expected: #. Selected: @.",
            )
            raise ValueError(message.replace("$", "Serpent").replace("#", f"{expected} bits").replace("@", f"{key_length} bits"))

    @staticmethod
    def _check_cancelled(
        should_cancel: CancelCallback,
    ) -> None:
        if should_cancel():
            raise RuntimeError("CANCELLED")

    def _message(
        self,
        key: str,
        fallback: str,
    ) -> str:
        if self.lang:
            return self.lang.t(key)

        return fallback