from abc import ABC, abstractmethod
from typing import Any, BinaryIO, Callable


CancelCallback = Callable[[], bool]
ProgressCallback = Callable[[int], None]


class StreamCipher(ABC):
    chunk_size = 64 * 1024

    @abstractmethod
    def encrypt_stream(
        self,
        fin: BinaryIO,
        fout: BinaryIO,
        key: bytes,
        params: dict[str, Any],
        should_cancel: CancelCallback,
        report_progress: ProgressCallback,
        aad: bytes = b"",
    ) -> None:
        pass

    @abstractmethod
    def decrypt_stream(
        self,
        fin: BinaryIO,
        fout: BinaryIO,
        key: bytes,
        params: dict[str, Any],
        should_cancel: CancelCallback,
        report_progress: ProgressCallback,
        aad: bytes = b"",
    ) -> None:
        pass

class Signer(ABC):
    chunk_size = 64 * 1024

    @abstractmethod
    def sign_stream(
        self,
        fin: BinaryIO,
        private_key: bytes,
        params: dict[str, Any] | None = None,
        should_cancel: CancelCallback = lambda: False,
        report_progress: ProgressCallback = lambda _: None,
    ) -> bytes:
        ...

    @abstractmethod
    def verify_stream(
        self,
        fin: BinaryIO,
        public_key: bytes,
        signature: bytes,
        params: dict[str, Any] | None = None,
        should_cancel: CancelCallback = lambda: False,
        report_progress: ProgressCallback = lambda _: None,
    ) -> bool:
        ...