from typing import Any, BinaryIO

from Crypto.Hash import SHA512, SHAKE256
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from .base import CancelCallback, ProgressCallback, Signer


SUPPORTED_CURVES = {
    "Ed25519": SHA512,
    "Ed448": SHAKE256,
}


class EdDSASigner(Signer):
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
        curve = params.get("curve", "Ed25519")

        ecc_key = self._import_private_key(private_key)
        self._validate_curve(ecc_key, curve)

        msg_hash = self._hash_stream(
            fin,
            curve,
            should_cancel,
            report_progress,
        )

        self._check_cancelled(should_cancel)

        try:
            signer = eddsa.new(
                ecc_key,
                "rfc8032",
            )
            return signer.sign(msg_hash)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "operations.error.18",
                    "EdDSA signing failed.",
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
        curve = params.get("curve", "Ed25519")

        ecc_key = self._import_public_key(public_key)
        self._validate_curve(ecc_key, curve)

        msg_hash = self._hash_stream(
            fin,
            curve,
            should_cancel,
            report_progress,
        )

        self._check_cancelled(should_cancel)

        verifier = eddsa.new(
            ecc_key,
            "rfc8032",
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
        curve: str,
        should_cancel: CancelCallback,
        report_progress: ProgressCallback,
    ):
        hash_module = self._get_hash_module(curve)
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

    def _get_hash_module(self, curve: str):
        try:
            return SUPPORTED_CURVES[curve]
        except KeyError as exc:
            raise ValueError(
                self._message(
                    "operations.error.19",
                    "EdDSA curve not supported.",
                )
            ) from exc

    def _import_private_key(self, key_data: bytes):
        try:
            key = ECC.import_key(key_data)
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

        if key.curve not in SUPPORTED_CURVES:
            raise ValueError(
                self._message(
                    "key.error.4",
                    "This is not a valid private key.",
                )
            )

        return key

    def _import_public_key(self, key_data: bytes):
        try:
            key = ECC.import_key(key_data)
        except (ValueError, IndexError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "key.error.5",
                    "This is not a valid public key.",
                )
            ) from exc

        if key.curve not in SUPPORTED_CURVES:
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
        if selected_curve not in SUPPORTED_CURVES:
            raise ValueError(
                self._message(
                    "operations.error.19",
                    "EdDSA curve not supported.",
                )
            )

        if key.curve != selected_curve:
            message = self._message(
                "key.error.13",
                "Selected curve does not match the key. Key: $. Selected: #.",
            )

            raise ValueError(
                message
                .replace("$", key.curve)
                .replace("#", selected_curve)
            )

    @staticmethod
    def _check_cancelled(
        should_cancel: CancelCallback,
    ):
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