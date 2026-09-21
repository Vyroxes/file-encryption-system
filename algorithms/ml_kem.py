import tempfile
from typing import Any, BinaryIO

from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

from .base import CancelCallback, ProgressCallback, StreamCipher
from .pqc import ML_KEM_MODULES


AES_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
KEM_LENGTH_SIZE = 2
SPOOL_SIZE = 8 * 1024 * 1024

KDF_CONTEXT = b"FileEncryptionSystem/ML-KEM/AES-256-GCM"


class MLKEMStream(StreamCipher):
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

        parameter_set = params.get(
            "parameter_set",
            "ML-KEM-768",
        )

        module = self._get_module(parameter_set)

        self._validate_public_key(
            key,
            module,
        )

        self._check_cancelled(
            should_cancel
        )

        try:
            kem_ciphertext, shared_secret = (
                module.encaps(key)
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "operations.error.22",
                    "ML-KEM encapsulation failed.",
                )
            ) from exc

        aes_key = self._derive_key(
            shared_secret
        )

        nonce = get_random_bytes(
            NONCE_SIZE
        )

        kem_length = len(
            kem_ciphertext
        ).to_bytes(
            KEM_LENGTH_SIZE,
            "big",
        )

        fout.write(kem_length)
        fout.write(kem_ciphertext)
        fout.write(nonce)

        cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=nonce,
        )

        cipher.update(
            aad
            + kem_length
            + kem_ciphertext
            + nonce
        )

        while True:
            self._check_cancelled(
                should_cancel
            )

            chunk = fin.read(
                self.chunk_size
            )

            if not chunk:
                break

            ciphertext = cipher.encrypt(
                chunk
            )

            fout.write(ciphertext)

            report_progress(
                len(chunk)
            )

        self._check_cancelled(
            should_cancel
        )

        fout.write(
            cipher.digest()
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

        parameter_set = params.get(
            "parameter_set",
            "ML-KEM-768",
        )

        module = self._get_module(
            parameter_set
        )

        self._validate_private_key(
            key,
            module,
        )

        length_data = fin.read(
            KEM_LENGTH_SIZE
        )

        if len(length_data) != KEM_LENGTH_SIZE:
            raise ValueError(
                self._message(
                    "operations.error.14",
                    "Invalid encrypted data.",
                )
            )

        kem_length = int.from_bytes(
            length_data,
            "big",
        )

        if kem_length != module.CIPHERTEXT_SIZE:
            raise ValueError(
                self._message(
                    "operations.error.14",
                    "Invalid encrypted data.",
                )
            )

        kem_ciphertext = fin.read(
            kem_length
        )

        if len(kem_ciphertext) != kem_length:
            raise ValueError(
                self._message(
                    "operations.error.14",
                    "Invalid encrypted data.",
                )
            )

        nonce = fin.read(
            NONCE_SIZE
        )

        if len(nonce) != NONCE_SIZE:
            raise ValueError(
                self._message(
                    "operations.error.14",
                    "Invalid encrypted data.",
                )
            )

        self._check_cancelled(
            should_cancel
        )

        try:
            shared_secret = module.decaps(
                key,
                kem_ciphertext,
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "operations.error.23",
                    "ML-KEM decapsulation failed.",
                )
            ) from exc

        aes_key = self._derive_key(
            shared_secret
        )

        cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=nonce,
        )

        cipher.update(
            aad
            + length_data
            + kem_ciphertext
            + nonce
        )

        tail = b""

        with tempfile.SpooledTemporaryFile(
            max_size=SPOOL_SIZE
        ) as plaintext:
            while True:
                self._check_cancelled(
                    should_cancel
                )

                chunk = fin.read(
                    self.chunk_size
                )

                if not chunk:
                    break

                data = tail + chunk

                if len(data) <= TAG_SIZE:
                    tail = data
                    continue

                ciphertext = data[:-TAG_SIZE]
                tail = data[-TAG_SIZE:]

                plaintext.write(
                    cipher.decrypt(
                        ciphertext
                    )
                )

                report_progress(
                    len(ciphertext)
                )

            if len(tail) != TAG_SIZE:
                raise ValueError(
                    self._message(
                        "operations.error.14",
                        "Invalid encrypted data.",
                    )
                )

            self._check_cancelled(
                should_cancel
            )

            try:
                cipher.verify(tail)
            except ValueError as exc:
                raise ValueError(
                    self._message(
                        "operations.error.2",
                        "Integrity check failed.",
                    )
                ) from exc

            plaintext.seek(0)

            while True:
                self._check_cancelled(
                    should_cancel
                )

                chunk = plaintext.read(
                    self.chunk_size
                )

                if not chunk:
                    break

                fout.write(chunk)

    def _get_module(
        self,
        parameter_set: str,
    ):
        try:
            return ML_KEM_MODULES[
                parameter_set
            ]
        except KeyError as exc:
            raise ValueError(
                self._message(
                    "operations.error.26",
                    "PQC parameter set not supported.",
                )
            ) from exc

    def _validate_public_key(
        self,
        key: bytes,
        module,
    ):
        if len(key) != module.PUBLIC_KEY_SIZE:
            raise ValueError(
                self._message(
                    "key.error.5",
                    "This is not a valid public key.",
                )
            )

    def _validate_private_key(
        self,
        key: bytes,
        module,
    ):
        if len(key) != module.SECRET_KEY_SIZE:
            raise ValueError(
                self._message(
                    "key.error.4",
                    "This is not a valid private key.",
                )
            )

    @staticmethod
    def _derive_key(
        shared_secret: bytes,
    ) -> bytes:
        return HKDF(
            shared_secret,
            AES_KEY_SIZE,
            b"",
            SHA3_256,
            context=KDF_CONTEXT,
        )

    @staticmethod
    def _check_cancelled(
        should_cancel: CancelCallback,
    ):
        if should_cancel():
            raise RuntimeError(
                "CANCELLED"
            )

    def _message(
        self,
        key: str,
        fallback: str,
    ) -> str:
        if self.lang:
            return self.lang.t(key)

        return fallback