import hmac
import tempfile
from typing import Any, BinaryIO

from Crypto.Random import get_random_bytes
from skein import skein256, skein512, skein1024, threefish

from .base import CancelCallback, ProgressCallback, StreamCipher


TWEAK_SIZE = 16
TAG_SIZE = 32
SPOOL_SIZE = 8 * 1024 * 1024

KDF_PERSONALIZATION = b"FES-Threefish-KDF-v1"
MAC_PERSONALIZATION = b"FES-Threefish-Skein-MAC-v1"

HASHERS = {
    32: skein256,
    64: skein512,
    128: skein1024,
}


class ThreefishSkeinMACStream(StreamCipher):
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

        enc_key, mac_key, hasher = self._derive_keys(key)

        tweak = get_random_bytes(TWEAK_SIZE)
        cipher = threefish(enc_key, tweak)
        mac = self._create_mac(hasher, mac_key, aad, tweak)

        fout.write(tweak)

        counter = 0

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            ciphertext, counter = self._crypt_chunk(
                cipher,
                chunk,
                counter,
            )

            mac.update(ciphertext)
            fout.write(ciphertext)
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)
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
        self._validate_key(key)

        tweak = fin.read(TWEAK_SIZE)

        if len(tweak) != TWEAK_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        enc_key, mac_key, hasher = self._derive_keys(key)

        cipher = threefish(enc_key, tweak)
        mac = self._create_mac(hasher, mac_key, aad, tweak)

        counter = 0
        tail = b""

        with tempfile.SpooledTemporaryFile(max_size=SPOOL_SIZE) as plaintext:
            while True:
                self._check_cancelled(should_cancel)

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                data = tail + chunk

                if len(data) <= TAG_SIZE:
                    tail = data
                    continue

                ciphertext = data[:-TAG_SIZE]
                tail = data[-TAG_SIZE:]

                mac.update(ciphertext)

                decrypted, counter = self._crypt_chunk(
                    cipher,
                    ciphertext,
                    counter,
                )

                plaintext.write(decrypted)
                report_progress(len(ciphertext))

            if len(tail) != TAG_SIZE:
                raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

            self._check_cancelled(should_cancel)

            if not hmac.compare_digest(mac.digest(), tail):
                raise ValueError(self._message("operations.error.2", "Authentication failed."))

            plaintext.seek(0)

            while True:
                self._check_cancelled(should_cancel)

                chunk = plaintext.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(chunk)

    @staticmethod
    def _crypt_chunk(cipher, data: bytes, counter: int) -> tuple[bytes, int]:
        block_size = cipher.block_size
        output = bytearray(len(data))
        offset = 0

        while offset < len(data):
            counter_block = counter.to_bytes(block_size, "big")
            keystream = cipher.encrypt_block(counter_block)

            length = min(
                block_size,
                len(data) - offset,
            )

            for index in range(length):
                output[offset + index] = data[offset + index] ^ keystream[index]

            offset += length
            counter += 1

        return bytes(output), counter

    def _derive_keys(self, key: bytes):
        hasher = HASHERS[len(key)]

        enc_key = hasher(
            key=key,
            key_id=b"encryption",
            pers=KDF_PERSONALIZATION,
            digest_bits=len(key) * 8,
        ).digest()

        mac_key = hasher(
            key=key,
            key_id=b"authentication",
            pers=KDF_PERSONALIZATION,
            digest_bits=256,
        ).digest()

        return enc_key, mac_key, hasher

    @staticmethod
    def _create_mac(hasher, mac_key: bytes, aad: bytes, tweak: bytes):
        mac = hasher(
            key=mac_key,
            pers=MAC_PERSONALIZATION,
            digest_bits=TAG_SIZE * 8,
        )

        mac.update(len(aad).to_bytes(8, "big"))
        mac.update(aad)
        mac.update(tweak)

        return mac

    def _validate_key(self, key: bytes):
        key_length = len(key) * 8

        if len(key) not in HASHERS:
            message = self._message("key.error.6", "Invalid key length for the $ algorithm. Expected: #. Selected: @.")
            raise ValueError(message.replace("$", "Threefish-Skein-MAC").replace("#", "256, 512 or 1024 bits").replace("@", f"{key_length} bits"))

    @staticmethod
    def _check_cancelled(should_cancel):
        if should_cancel():
            raise RuntimeError("CANCELLED")

    def _message(self, key, fallback):
        if self.lang:
            return self.lang.t(key)

        return fallback