import tempfile
from typing import Any, BinaryIO

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import (
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
)
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes

from .base import CancelCallback, ProgressCallback, StreamCipher, Signer


HASHES = {
    "SHA-256": SHA256,
    "SHA-384": SHA384,
    "SHA-512": SHA512,
    "SHA3-256": SHA3_256,
    "SHA3-384": SHA3_384,
    "SHA3-512": SHA3_512,
}

AES_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
RSA_KEY_LENGTH_SIZE = 2
SPOOL_SIZE = 8 * 1024 * 1024
VALID_KEY_LENGTHS = (2048, 3072, 4096)


class RSAOAEPStream(StreamCipher):
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
        hash_name = params.get("hash", "SHA-256")

        hash_module = self._get_hash(hash_name)
        public_key = self._import_public_key(key)

        self._validate_key_length(public_key)

        aes_key = get_random_bytes(AES_KEY_SIZE)

        rsa_cipher = PKCS1_OAEP.new(
            public_key,
            hashAlgo=hash_module,
        )

        encrypted_key = rsa_cipher.encrypt(aes_key)

        nonce = get_random_bytes(NONCE_SIZE)
        aes_cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=nonce,
        )

        if aad:
            aes_cipher.update(aad)

        fout.write(len(encrypted_key).to_bytes(RSA_KEY_LENGTH_SIZE, "big"))
        fout.write(encrypted_key)
        fout.write(nonce)

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            fout.write(aes_cipher.encrypt(chunk))
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)
        fout.write(aes_cipher.digest())

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
        hash_name = params.get("hash", "SHA-256")

        hash_module = self._get_hash(hash_name)
        private_key = self._import_private_key(key)

        self._validate_key_length(private_key)

        length_data = fin.read(RSA_KEY_LENGTH_SIZE)

        if len(length_data) != RSA_KEY_LENGTH_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        encrypted_key_length = int.from_bytes(length_data, "big")
        expected_length = private_key.size_in_bytes()

        if encrypted_key_length != expected_length:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        encrypted_key = fin.read(encrypted_key_length)

        if len(encrypted_key) != encrypted_key_length:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        nonce = fin.read(NONCE_SIZE)

        if len(nonce) != NONCE_SIZE:
            raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

        try:
            rsa_cipher = PKCS1_OAEP.new(
                private_key,
                hashAlgo=hash_module,
            )
            aes_key = rsa_cipher.decrypt(encrypted_key)
        except ValueError as exc:
            raise ValueError(self._message("operations.error.17", "RSA-OAEP decryption failed.")) from exc

        aes_cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=nonce,
        )

        if aad:
            aes_cipher.update(aad)

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

                plaintext.write(aes_cipher.decrypt(ciphertext))
                report_progress(len(ciphertext))

            if len(tail) != TAG_SIZE:
                raise ValueError(self._message("operations.error.14", "Invalid encrypted data."))

            self._check_cancelled(should_cancel)

            try:
                aes_cipher.verify(tail)
            except ValueError as exc:
                raise ValueError(self._message("operations.error.2", "Integrity check failed.")) from exc

            plaintext.seek(0)

            while True:
                self._check_cancelled(should_cancel)

                chunk = plaintext.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(chunk)

    def _get_hash(self, hash_name: str):
        try:
            return HASHES[hash_name]
        except KeyError as exc:
            raise ValueError(self._message("operations.error.16", "Hash function not supported.")) from exc

    def _import_public_key(self, key_data: bytes):
        try:
            key = RSA.import_key(key_data)
        except (ValueError, IndexError, TypeError) as exc:
            raise ValueError(self._message("key.error.5", "This is not a valid public key.")) from exc

        return key.public_key()

    def _import_private_key(self, key_data: bytes):
        try:
            key = RSA.import_key(key_data)
        except (ValueError, IndexError, TypeError) as exc:
            raise ValueError(self._message("key.error.4", "This is not a valid private key.")) from exc

        if not key.has_private():
            raise ValueError(self._message("key.error.4", "This is not a valid private key."))

        return key

    def _validate_key_length(self, key):
        key_length = key.size_in_bits()

        if key_length not in VALID_KEY_LENGTHS:
            expected = ", ".join(str(length) for length in VALID_KEY_LENGTHS)
            message = self._message("key.error.6", "Invalid key length for the $ algorithm. Expected: #. Selected: @.")
            raise ValueError(message.replace("$", "RSA-OAEP").replace("#", f"{expected} bits").replace("@", f"{key_length} bits"))

    @staticmethod
    def _check_cancelled(should_cancel):
        if should_cancel():
            raise RuntimeError("CANCELLED")

    def _message(self, key, fallback):
        if self.lang:
            return self.lang.t(key)

        return fallback

class RSAPSSSigner(Signer):
    def __init__(self, lang=None):
        self.lang = lang

    def sign_stream(
        self,
        fin: BinaryIO,
        private_key: bytes,
        params: dict[str, Any] | None = None,
        should_cancel: CancelCallback = lambda: False,
        report_progress: ProgressCallback = lambda _: None,
    ) -> bytes:
        params = params or {}
        hash_name = params.get("hash", "SHA-256")

        hash_module = self._get_hash(hash_name)
        rsa_key = self._import_private_key(private_key)
        self._validate_key_length(rsa_key)

        msg_hash = self._hash_stream(
            fin,
            hash_module,
            should_cancel,
            report_progress,
        )

        self._check_cancelled(should_cancel)

        try:
            signer = pss.new(
                rsa_key,
                salt_bytes=msg_hash.digest_size,
            )
            return signer.sign(msg_hash)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "operations.error.15",
                    "RSA-PSS signing failed.",
                )
            ) from exc

    def verify_stream(
        self,
        fin: BinaryIO,
        public_key: bytes,
        signature: bytes,
        params: dict[str, Any] | None = None,
        should_cancel: CancelCallback = lambda: False,
        report_progress: ProgressCallback = lambda _: None,
    ) -> bool:
        params = params or {}
        hash_name = params.get("hash", "SHA-256")

        hash_module = self._get_hash(hash_name)
        rsa_key = self._import_public_key(public_key)
        self._validate_key_length(rsa_key)

        msg_hash = self._hash_stream(
            fin,
            hash_module,
            should_cancel,
            report_progress,
        )

        self._check_cancelled(should_cancel)

        verifier = pss.new(
            rsa_key,
            salt_bytes=msg_hash.digest_size,
        )

        try:
            verifier.verify(msg_hash, signature)
        except (ValueError, TypeError):
            return False

        return True

    def _hash_stream(
        self,
        fin,
        hash_module,
        should_cancel,
        report_progress,
    ):
        msg_hash = hash_module.new()

        while True:
            self._check_cancelled(should_cancel)

            chunk = fin.read(self.chunk_size)
            if not chunk:
                break

            msg_hash.update(chunk)
            report_progress(len(chunk))

        self._check_cancelled(should_cancel)

        return msg_hash

    def _get_hash(self, hash_name: str):
        try:
            return HASHES[hash_name]
        except KeyError as exc:
            raise ValueError(
                self._message(
                    "operations.error.16",
                    "Hash function not supported.",
                )
            ) from exc

    def _import_private_key(self, key_data: bytes):
        try:
            key = RSA.import_key(key_data)
        except (ValueError, IndexError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "key.error.4",
                    "This is not a valid private key.",
                )
            ) from exc

        if not key.has_private():
            raise ValueError(
                self._message(
                    "key.error.4",
                    "This is not a valid private key.",
                )
            )

        return key

    def _import_public_key(self, key_data: bytes):
        try:
            key = RSA.import_key(key_data)
        except (ValueError, IndexError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "key.error.5",
                    "This is not a valid public key.",
                )
            ) from exc

        return key.public_key()

    def _validate_key_length(self, key):
        key_length = key.size_in_bits()

        if key_length not in VALID_KEY_LENGTHS:
            expected = ", ".join(str(length) for length in VALID_KEY_LENGTHS)
            message = self._message(
                "key.error.6",
                "Invalid key length for the $ algorithm. Expected: #. Selected: @.",
            )
            raise ValueError(
                message
                .replace("$", "RSA-PSS")
                .replace("#", f"{expected} bits")
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