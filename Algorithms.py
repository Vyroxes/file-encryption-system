import base64
import os
import tempfile
import json
import struct
import base64
from abc import ABC, abstractmethod
from typing import BinaryIO, Callable, Dict, Any
from PySide6.QtCore import QThread, Signal
from Crypto.Cipher import AES, DES3, PKCS1_OAEP, PKCS1_v1_5, ChaCha20_Poly1305, Salsa20
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Signature import pss, eddsa, DSS
from Crypto.Util.Padding import pad, unpad
from skein import skein256, skein512, skein1024, StreamCipher
from pyserpent import Serpent
from xycrypto.ciphers import Camellia
from ascon import encrypt, decrypt, hash

ALGORITHMS = {
    "AES": {
        "type": "symmetric",
        "key_lengths": [256, 192, 128],
        "modes": ["GCM (AEAD)", "EAX (AEAD)", "SIV (AEAD)", "CCM (AEAD)", "OCB (AEAD)", "CTR", "CBC", "ECB"]
    },
    "ASCON": {
        "type": "symmetric",
        "key_lengths": [128, 128, 160],
        "modes": ["Ascon-128 (AEAD)", "Ascon-128a (AEAD)", "Ascon-80pq (AEAD)"]
    },
    "Serpent": {
        "type": "symmetric",
        "key_lengths": [256, 192, 128],
        "modes": ["CBC"]
    },
    "Camellia": {
        "type": "symmetric",
        "key_lengths": [256, 192, 128],
        "modes": ["CTR", "CBC"]
    },
    "3DES": {
        "type": "symmetric",
        "key_lengths": [192],
        "modes": ["EAX (AEAD)", "CTR", "CFB", "OFB"]
    },
    "XChaCha20-Poly1305": {
        "type": "symmetric",
        "key_lengths": [256],
    },
    "Salsa20": {
        "type": "symmetric",
        "key_lengths": [256],
    },
    "Threefish-Skein-MAC": {
        "type": "symmetric",
        "key_lengths": [1024, 512, 256],
    },
    "RSA-PSS": {
        "type": "asymmetric",
        "key_lengths": [3072, 2048, 1024],
        "paddings": ["OAEP", "PKCS#1 v1.5"],
        "hashes": ["SHA3-512", "SHA3-384", "SHA3-256", "SHA-512", "SHA-384", "SHA-256"],
    },
    "EdDSA": {
        "type": "asymmetric",
        "curves": ["Ed25519", "Ed448"],
    },
    "ECDSA": {
        "type": "asymmetric",
        "curves": ["P-521 (secp521r1)", "P-384 (secp384r1)", "P-256 (secp256r1)"],
    },
}

def atomic_write_bytes(dst_path: str, data: bytes) -> None:
    dirn = os.path.dirname(os.path.abspath(dst_path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".atomic_write_", suffix=".tmp", dir=dirn)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, dst_path)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        raise

def generate_key(key_type: str, public: bool, private_key_path: str, algorithm_name: str, key_length_bits: int, output_path: str) -> str:
    algorithm = ALGORITHMS.get(algorithm_name)
    if not algorithm or key_type != algorithm["type"]:
        raise ValueError("Invalid algorithm")

    message = "public key" if public else "private key" if key_type == "asymmetric" else "key"
    if key_length_bits not in algorithm["key_lengths"]:
        raise ValueError(f"Invalid {message} length")

    if algorithm_name == "3DES":
        while True:
            candidate = get_random_bytes(24)
            key = DES3.adjust_key_parity(candidate)
            try:
                DES3.new(key, DES3.MODE_EAX)
                break
            except ValueError:
                continue

    elif algorithm_name == "RSA-PSS":
        if public:
            with open(private_key_path, "rb") as f:
                rsa_key = RSA.import_key(f.read())
            key = rsa_key.publickey().export_key(format="PEM")
        else:
            rsa_key = RSA.generate(key_length_bits)
            key = rsa_key.export_key(format="PEM")

    else:
        key_bytes = key_length_bits // 8
        key = get_random_bytes(key_bytes)

    atomic_write_bytes(output_path, key)

    return output_path

MAGIC = b"XYCR"
VERSION = 1

def write_header(fout, header: dict):
    data = json.dumps(header).encode("utf-8")
    fout.write(MAGIC)
    fout.write(struct.pack(">B", VERSION))
    fout.write(struct.pack(">I", len(data)))
    fout.write(data)

def read_header(fin, lang=None) -> dict:
    magic = fin.read(4)
    if magic != MAGIC:
        raise ValueError(lang.t("operations.error.8"))

    version = struct.unpack(">B", fin.read(1))[0]
    if version != VERSION:
        raise ValueError(lang.t("operations.error.8"))

    length = struct.unpack(">I", fin.read(4))[0]
    return json.loads(fin.read(length).decode("utf-8"))

class CryptoWorker(QThread):
    progress = Signal(int)
    finished = Signal(str)
    error = Signal(str)

    def __init__(
        self,
        operation: str,
        algorithm_name: str,
        input_file: str,
        output_file: str,
        key_path: str = None,
        private_key_path: str = None,
        public_key_path: str = None,
        params: dict | None = None,
        lang = None
    ):
        super().__init__()
        self._cancelled = False
        self.operation = operation
        self.algorithm_name = algorithm_name
        self.input_file = input_file
        self.output_file = output_file
        self.key_path = key_path
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.params = params or {}
        self.lang = lang

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            if self._cancelled:
                return

            algo = self._load_algorithm()

            if self.operation == "encrypt":
                self._encrypt(algo)
            elif self.operation == "decrypt":
                self._decrypt(algo)
            # elif self.operation == "sign":
            #     self._sign(algo)
            # elif self.operation == "verify":
            #     self._verify(algo)
            else:
                raise ValueError(self.lang.t("operations.error.10"))

            if not self._cancelled:
                self.progress.emit(100)
                self.finished.emit(self.output_file)

        except RuntimeError as e:
            if str(e) == "CANCELLED":
                # self.progress.emit(0)
                return
            self.error.emit(str(e))

        except Exception as e:
            self.error.emit(str(e))

    def _encrypt(self, algo):
        try:
            total_size = os.path.getsize(self.input_file)
            processed = 0

            def report_progress(written: int):
                nonlocal processed
                processed += written
                percent = int(processed * 100 / total_size)
                self.progress.emit(min(percent, 99))

            with open(self.input_file, "rb") as fin, open(self.output_file, "wb") as fout:
                if isinstance(algo, StreamCipher):
                    write_header(fout, {"algorithm": self.algorithm_name, "params": self.params})
                    key = self._load_key(self.key_path)
                    algo.encrypt_stream(fin, fout, key, self.params, lambda: self._cancelled, report_progress)

        finally:
            if self._cancelled and os.path.exists(self.output_file):
                os.remove(self.output_file)

    def _decrypt(self, algo):
        try:
            total_size = os.path.getsize(self.input_file)
            processed = 0

            def report_progress(written: int):
                nonlocal processed
                processed += written
                percent = int(processed * 100 / total_size)
                self.progress.emit(min(percent, 99))

            with open(self.input_file, "rb") as fin, open(self.output_file, "wb") as fout:
                if isinstance(algo, StreamCipher):
                    header = read_header(fin, lang=self.lang)
                    key = self._load_key(self.key_path)
                    algo.decrypt_stream(fin, fout, key, header["params"], lambda: self._cancelled, report_progress)

        finally:
            if self._cancelled and os.path.exists(self.output_file):
                os.remove(self.output_file)

    # def _sign(self, algo):
    #     with open(self.input_file, "rb") as fin:
    #         data = fin.read()
    #     if isinstance(algo, Signer):
    #         private_key = self._load_key(self.private_key_path)
    #         sig = algo.sign(data, private_key, self.params)
    #         with open(self.output_file, "wb") as fout:
    #             fout.write(sig)

    # def _verify(self, algo):
    #     with open(self.input_file, "rb") as fin:
    #         data = fin.read()
    #     if isinstance(algo, Signer):
    #         public_key = self._load_key(self.public_key_path)
    #         valid = algo.verify(data, public_key, self.params)
    #         with open(self.output_file, "w", encoding="utf-8") as fout:
    #             fout.write("VALID" if valid else "INVALID")

    def _load_algorithm(self):
        if self.algorithm_name == "AES":
            return AESStream(lang=self.lang)
        # elif self.algorithm_name == "3DES":
        #     return DES3Stream()
        # elif self.algorithm_name == "RSA-PSS":
        #     return RSAPSSSigner()
        # etc.
        else:
            raise ValueError(self.lang.t("operations.error.9"))

    def _load_key(self, path: str):
        if not path or not os.path.exists(path):
            raise FileNotFoundError(self.lang.t("key.error"))
        with open(path, "rb") as f:
            return f.read()
        
class StreamCipher(ABC):
    name: str

    @abstractmethod
    def encrypt_stream(
        self,
        fin: BinaryIO,
        fout: BinaryIO,
        key: bytes,
        params: Dict[str, Any],
        should_cancel: Callable[[], bool],
        report_progress: Callable[[int], None]
    ) -> Dict[str, Any]:
        ...

    @abstractmethod
    def decrypt_stream(
        self,
        fin: BinaryIO,
        fout: BinaryIO,
        key: bytes,
        params: Dict[str, Any],
        should_cancel: Callable[[], bool],
        report_progress: Callable[[int], None]
    ) -> None:
        ...

BLOCK_SIZE = 16

class AESStream(StreamCipher):
    chunk_size = 64 * 1024
    AEAD_MODES = ("GCM (AEAD)", "EAX (AEAD)")
    NON_STREAM_AEAD_MODES = ("SIV (AEAD)", "CCM (AEAD)", "OCB (AEAD)")

    def __init__(self, lang=None):
        self.lang = lang

    def encrypt_stream(self, fin: BinaryIO, fout: BinaryIO, key: bytes, params: Dict[str, Any] = None, should_cancel: Callable[[], bool] = lambda: False, report_progress: Callable[[int], None] = lambda x: None) -> Dict[str, Any]:
        params = params or {}
        mode_name = params.get("mode", "GCM (AEAD)")

        if mode_name in self.NON_STREAM_AEAD_MODES:
            data = fin.read()
            report_progress(len(data))
            if mode_name == "SIV (AEAD)":
                cipher = AES.new(key, AES.MODE_SIV)
                ciphertext, tag = cipher.encrypt_and_digest(data)
                fout.write(ciphertext)
                fout.write(tag)
                return {"mode": mode_name, "tag": base64.b64encode(tag).decode()}

            elif mode_name == "CCM (AEAD)":
                cipher = AES.new(key, AES.MODE_CCM, nonce=get_random_bytes(11))
                ciphertext, tag = cipher.encrypt_and_digest(data)
                fout.write(cipher.nonce)
                fout.write(ciphertext)
                fout.write(tag)
                return {"mode": mode_name, "nonce": base64.b64encode(cipher.nonce).decode(), "tag": base64.b64encode(tag).decode()}

            elif mode_name == "OCB (AEAD)":
                cipher = AES.new(key, AES.MODE_OCB, nonce=get_random_bytes(15))
                ciphertext, tag = cipher.encrypt_and_digest(data)
                fout.write(cipher.nonce)
                fout.write(ciphertext)
                fout.write(tag)
                return {"mode": mode_name, "nonce": base64.b64encode(cipher.nonce).decode(), "tag": base64.b64encode(tag).decode()}

        if mode_name in self.AEAD_MODES:
            nonce = get_random_bytes(12)
            cipher = AES.new(key, getattr(AES, f"MODE_{mode_name.split()[0]}"), nonce=nonce)
            fout.write(nonce)
            buffer = b""
            while True:
                if should_cancel():
                    raise RuntimeError("CANCELLED")

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                buffer += chunk
                report_progress(len(chunk))

                if len(buffer) >= BLOCK_SIZE:
                    to_encrypt = buffer[:len(buffer) - len(buffer)%BLOCK_SIZE]
                    buffer = buffer[len(to_encrypt):]
                    fout.write(cipher.encrypt(to_encrypt))

            if buffer:
                fout.write(cipher.encrypt(buffer))
            tag = cipher.digest()
            fout.write(tag)
            return

        elif mode_name in ("CBC", "ECB"):
            iv = get_random_bytes(16) if mode_name == "CBC" else None
            cipher = AES.new(key, AES.MODE_CBC, iv=iv) if mode_name=="CBC" else AES.new(key, AES.MODE_ECB)
            if iv:
                fout.write(iv)
            buffer = b""
            while True:
                if should_cancel():
                    raise RuntimeError("CANCELLED")

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                buffer += chunk
                report_progress(len(chunk))

                while len(buffer) >= BLOCK_SIZE:
                    fout.write(cipher.encrypt(buffer[:BLOCK_SIZE]))
                    buffer = buffer[BLOCK_SIZE:]

            if buffer:
                fout.write(cipher.encrypt(pad(buffer, BLOCK_SIZE)))
            return
        
        elif mode_name == "CTR":
            nonce = get_random_bytes(8)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            fout.write(nonce)
            while True:
                if should_cancel():
                    raise RuntimeError("CANCELLED")

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(cipher.encrypt(chunk))
                report_progress(len(chunk))
            return {"mode": mode_name, "nonce": base64.b64encode(nonce).decode()}

        else:
            raise ValueError(self.lang.t("operations.error.11"))

    def decrypt_stream(self, fin: BinaryIO, fout: BinaryIO, key: bytes, params: Dict[str, Any] = None, should_cancel: Callable[[], bool] = lambda: False, report_progress: Callable[[int], None] = lambda x: None) -> None:
        params = params or {}
        mode_name = params.get("mode", "GCM (AEAD)")

        if mode_name in self.NON_STREAM_AEAD_MODES:
            data = fin.read()
            report_progress(len(data))
            if mode_name == "SIV (AEAD)":
                ciphertext = data[:-16]
                tag = data[-16:]
                cipher = AES.new(key, AES.MODE_SIV)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                fout.write(plaintext)
                return

            elif mode_name == "CCM (AEAD)":
                nonce = data[:11]
                tag = data[-16:]
                ciphertext = data[11:-16]
                cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                fout.write(plaintext)
                return

            elif mode_name == "OCB (AEAD)":
                nonce = data[:15]
                tag = data[-16:]
                ciphertext = data[15:-16]
                cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                fout.write(plaintext)
                return

        if mode_name in self.AEAD_MODES:
            nonce = fin.read(12)
            cipher = AES.new(key, getattr(AES, f"MODE_{mode_name.split()[0]}"), nonce=nonce)

            fout_buffer = b""
            while True:
                if should_cancel():
                    raise RuntimeError("CANCELLED")

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                fout_buffer += chunk
                report_progress(len(chunk))

            tag = fout_buffer[-16:]
            ciphertext = fout_buffer[:-16]

            buffer = b""
            while len(ciphertext) >= BLOCK_SIZE:
                to_dec = ciphertext[:len(ciphertext) - len(ciphertext)%BLOCK_SIZE]
                buffer = cipher.decrypt(to_dec)
                fout.write(buffer)
                ciphertext = ciphertext[len(to_dec):]
            if ciphertext:
                fout.write(cipher.decrypt(ciphertext))

            try:
                cipher.verify(tag)
            except ValueError:
                raise ValueError(self.lang.t("operations.error.2"))
            return
        
        elif mode_name in ("CBC", "ECB"):
            iv = fin.read(16) if mode_name == "CBC" else None
            cipher = AES.new(key, AES.MODE_CBC, iv=iv) if mode_name=="CBC" else AES.new(key, AES.MODE_ECB)
            buffer = b""
            while True:
                if should_cancel():
                    raise RuntimeError("CANCELLED")

                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                buffer += chunk
                report_progress(len(chunk))

                while len(buffer) >= BLOCK_SIZE:
                    fout.write(cipher.decrypt(buffer[:BLOCK_SIZE]))
                    buffer = buffer[BLOCK_SIZE:]
                
            if buffer:
                fout.write(unpad(cipher.decrypt(buffer), BLOCK_SIZE))
            return
        
        elif mode_name == "CTR":
            nonce = fin.read(8)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            while True:
                if should_cancel():
                    raise RuntimeError("CANCELLED")
                
                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break

                fout.write(cipher.decrypt(chunk))
                report_progress(len(chunk))
            return

        else:
            raise ValueError(self.lang.t("operations.error.11"))