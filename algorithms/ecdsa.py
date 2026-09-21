from typing import Any, BinaryIO

from Crypto.Hash import (
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
)
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from .base import CancelCallback, ProgressCallback, Signer


HASHES = {
    "SHA-256": SHA256,
    "SHA-384": SHA384,
    "SHA-512": SHA512,
    "SHA3-256": SHA3_256,
    "SHA3-384": SHA3_384,
    "SHA3-512": SHA3_512,
}

CURVES = {
    "P-256 (secp256r1)": "P-256",
    "P-384 (secp384r1)": "P-384",
    "P-521 (secp521r1)": "P-521",
}


class ECDSASigner(Signer):
    chunk_size = 64 * 1024

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

        curve = params.get(
            "curve",
            "P-256 (secp256r1)",
        )
        hash_name = params.get(
            "hash",
            "SHA-256",
        )

        ecc_key = self._import_private_key(private_key)

        self._validate_curve(
            ecc_key,
            curve,
        )

        hash_module = self._get_hash(
            hash_name
        )

        msg_hash = self._hash_stream(
            fin,
            hash_module,
            should_cancel,
            report_progress,
        )

        self._check_cancelled(
            should_cancel
        )

        try:
            signer = DSS.new(
                ecc_key,
                "deterministic-rfc6979",
                encoding="der",
            )

            return signer.sign(
                msg_hash
            )

        except (ValueError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "operations.error.20",
                    "ECDSA signing failed.",
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

        curve = params.get(
            "curve",
            "P-256 (secp256r1)",
        )
        hash_name = params.get(
            "hash",
            "SHA-256",
        )

        ecc_key = self._import_public_key(
            public_key
        )

        self._validate_curve(
            ecc_key,
            curve,
        )

        hash_module = self._get_hash(
            hash_name
        )

        msg_hash = self._hash_stream(
            fin,
            hash_module,
            should_cancel,
            report_progress,
        )

        self._check_cancelled(
            should_cancel
        )

        verifier = DSS.new(
            ecc_key,
            "deterministic-rfc6979",
            encoding="der",
        )

        try:
            verifier.verify(
                msg_hash,
                signature,
            )
        except (ValueError, TypeError):
            return False

        return True

    def _hash_stream(
        self,
        fin: BinaryIO,
        hash_module,
        should_cancel: CancelCallback,
        report_progress: ProgressCallback,
    ):
        msg_hash = hash_module.new()

        while True:
            self._check_cancelled(
                should_cancel
            )

            chunk = fin.read(
                self.chunk_size
            )

            if not chunk:
                break

            msg_hash.update(chunk)

            report_progress(
                len(chunk)
            )

        self._check_cancelled(
            should_cancel
        )

        return msg_hash

    def _get_hash(
        self,
        hash_name: str,
    ):
        try:
            return HASHES[hash_name]

        except KeyError as exc:
            raise ValueError(
                self._message(
                    "operations.error.16",
                    "Hash function not supported.",
                )
            ) from exc

    def _import_private_key(
        self,
        key_data: bytes,
    ):
        try:
            key = ECC.import_key(
                key_data
            )

        except (
            ValueError,
            IndexError,
            TypeError,
        ) as exc:
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

        if key.curve not in CURVES.values():
            raise ValueError(
                self._message(
                    "key.error.4",
                    "This is not a valid private key.",
                )
            )

        return key

    def _import_public_key(
        self,
        key_data: bytes,
    ):
        try:
            key = ECC.import_key(
                key_data
            )

        except (
            ValueError,
            IndexError,
            TypeError,
        ) as exc:
            raise ValueError(
                self._message(
                    "key.error.5",
                    "This is not a valid public key.",
                )
            ) from exc

        if key.curve not in CURVES.values():
            raise ValueError(
                self._message(
                    "key.error.5",
                    "This is not a valid public key.",
                )
            )

        return key.public_key()

    def _validate_curve(
        self,
        key,
        selected_curve: str,
    ):
        try:
            expected_curve = CURVES[
                selected_curve
            ]

        except KeyError as exc:
            raise ValueError(
                self._message(
                    "operations.error.21",
                    "ECDSA curve not supported.",
                )
            ) from exc

        if key.curve != expected_curve:
            message = self._message(
                "key.error.13",
                "Selected curve does not match the key. Key: $. Selected: #.",
            )

            raise ValueError(
                message
                .replace(
                    "$",
                    key.curve,
                )
                .replace(
                    "#",
                    expected_curve,
                )
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