from hmac import compare_digest
from tempfile import SpooledTemporaryFile
from typing import Any, BinaryIO

from Crypto.Random import get_random_bytes

from ._ascon_nist import (
    ascon_finalize,
    ascon_initialize,
    ascon_permutation,
    ascon_process_associated_data,
    ascon_process_ciphertext,
    ascon_process_plaintext,
    bytes_to_int,
    int_to_bytes,
)
from .base import CancelCallback, ProgressCallback, StreamCipher


KEY_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16
RATE = 16
A_ROUNDS = 12
B_ROUNDS = 8
VERSION = 1
MODE_NAME = "Ascon-128 (AEAD)"


class AsconStream(StreamCipher):
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
        self._validate_key(key, mode_name)

        nonce = get_random_bytes(NONCE_SIZE)
        state = self._initialize_state(key, nonce, aad)

        fout.write(nonce)

        buffer = b""

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            report_progress(len(chunk))
            data = buffer + chunk
            process_length = len(data) - (len(data) % RATE)

            if process_length:
                fout.write(
                    self._encrypt_blocks(
                        state,
                        data[:process_length],
                    )
                )

            buffer = data[process_length:]

        fout.write(
            ascon_process_plaintext(
                state,
                B_ROUNDS,
                RATE,
                buffer,
            )
        )

        fout.write(
            ascon_finalize(
                state,
                RATE,
                A_ROUNDS,
                key,
            )
        )

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
        self._validate_key(key, mode_name)

        nonce = fin.read(NONCE_SIZE)

        if len(nonce) != NONCE_SIZE:
            raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

        state = self._initialize_state(key, nonce, aad)
        buffer = b""

        with SpooledTemporaryFile(max_size=self.spool_size, mode="w+b") as plaintext_file:
            while True:
                self._check_cancelled(should_cancel)

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                report_progress(len(chunk))
                data = buffer + chunk

                process_length = max(0, len(data) - TAG_SIZE)
                process_length -= process_length % RATE

                if process_length:
                    plaintext_file.write(
                        self._decrypt_blocks(
                            state,
                            data[:process_length],
                        )
                    )

                buffer = data[process_length:]

            if len(buffer) < TAG_SIZE:
                raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

            ciphertext_tail = buffer[:-TAG_SIZE]
            tag = buffer[-TAG_SIZE:]

            if len(ciphertext_tail) >= RATE:
                raise ValueError(self._message("operations.error.8", "Invalid encrypted file"))

            plaintext_file.write(
                ascon_process_ciphertext(
                    state,
                    B_ROUNDS,
                    RATE,
                    ciphertext_tail,
                )
            )

            expected_tag = ascon_finalize(
                state,
                RATE,
                A_ROUNDS,
                key,
            )

            if not compare_digest(expected_tag, tag):
                raise ValueError(self._message("operations.error.2", "Authentication failed"))

            plaintext_file.seek(0)

            while True:
                self._check_cancelled(should_cancel)

                chunk = plaintext_file.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(chunk)

    @staticmethod
    def _initialize_state(
        key: bytes,
        nonce: bytes,
        aad: bytes,
    ) -> list[int]:
        state = [0, 0, 0, 0, 0]

        ascon_initialize(
            state,
            len(key) * 8,
            RATE,
            A_ROUNDS,
            B_ROUNDS,
            VERSION,
            key,
            nonce,
        )

        ascon_process_associated_data(
            state,
            B_ROUNDS,
            RATE,
            aad,
        )

        return state

    @staticmethod
    def _encrypt_blocks(
        state: list[int],
        data: bytes,
    ) -> bytes:
        output = bytearray()

        for offset in range(0, len(data), RATE):
            block = data[offset:offset + RATE]

            state[0] ^= bytes_to_int(block[:8])
            state[1] ^= bytes_to_int(block[8:16])

            output.extend(int_to_bytes(state[0], 8))
            output.extend(int_to_bytes(state[1], 8))

            ascon_permutation(state, B_ROUNDS)

        return bytes(output)

    @staticmethod
    def _decrypt_blocks(
        state: list[int],
        data: bytes,
    ) -> bytes:
        output = bytearray()

        for offset in range(0, len(data), RATE):
            block = data[offset:offset + RATE]

            ciphertext_0 = bytes_to_int(block[:8])
            ciphertext_1 = bytes_to_int(block[8:16])

            output.extend(
                int_to_bytes(
                    state[0] ^ ciphertext_0,
                    8,
                )
            )

            output.extend(
                int_to_bytes(
                    state[1] ^ ciphertext_1,
                    8,
                )
            )

            state[0] = ciphertext_0
            state[1] = ciphertext_1

            ascon_permutation(state, B_ROUNDS)

        return bytes(output)

    def _validate_mode(self, mode_name: str) -> None:
        if mode_name != MODE_NAME:
            raise ValueError(self._message("operations.error.11", "Unsupported ASCON mode"))

    def _validate_key(
        self,
        key: bytes,
        mode_name: str,
    ) -> None:
        key_length = len(key) * 8

        if len(key) != KEY_SIZE:
            message = self._message(
                "key.error.6",
                "Invalid key length for the $ algorithm. Expected: #. Selected: @.",
            )
            raise ValueError(message.replace("$", mode_name).replace("#", "128 bits").replace("@", f"{key_length} bits"))

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