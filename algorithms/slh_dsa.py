from typing import Any, BinaryIO

from pqcrypto import InvalidSignatureError

from .base import CancelCallback, ProgressCallback, Signer
from .pqc import SLH_DSA_MODULES


class SLHDSASigner(Signer):
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

        parameter_set = params.get(
            "parameter_set",
            "SLH-DSA-SHAKE-256s",
        )

        module = self._get_module(
            parameter_set
        )

        self._validate_private_key(
            private_key,
            module,
        )

        message = self._read_message(
            fin,
            should_cancel,
            report_progress,
        )

        self._check_cancelled(
            should_cancel
        )

        try:
            return module.sign(
                private_key,
                message,
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(
                self._message(
                    "operations.error.25",
                    "SLH-DSA signing failed.",
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

        parameter_set = params.get(
            "parameter_set",
            "SLH-DSA-SHAKE-256s",
        )

        module = self._get_module(
            parameter_set
        )

        self._validate_public_key(
            public_key,
            module,
        )

        if len(signature) != module.SIGNATURE_SIZE:
            return False

        message = self._read_message(
            fin,
            should_cancel,
            report_progress,
        )

        self._check_cancelled(
            should_cancel
        )

        try:
            module.verify(
                public_key,
                message,
                signature,
            )
        except InvalidSignatureError:
            return False
        except (ValueError, TypeError):
            return False

        return True

    def _read_message(
        self,
        fin: BinaryIO,
        should_cancel: CancelCallback,
        report_progress: ProgressCallback,
    ) -> bytes:
        message = bytearray()

        while True:
            self._check_cancelled(
                should_cancel
            )

            chunk = fin.read(
                self.chunk_size
            )

            if not chunk:
                break

            message.extend(chunk)

            report_progress(
                len(chunk)
            )

        self._check_cancelled(
            should_cancel
        )

        return bytes(message)

    def _get_module(
        self,
        parameter_set: str,
    ):
        try:
            return SLH_DSA_MODULES[
                parameter_set
            ]
        except KeyError as exc:
            raise ValueError(
                self._message(
                    "operations.error.26",
                    "PQC parameter set not supported.",
                )
            ) from exc

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