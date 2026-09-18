from PyQt5.QtWidgets import QMenu, QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog, QLabel, QMessageBox, QComboBox, QProgressBar, QGroupBox, QHBoxLayout, QCheckBox
from PyQt5.QtWinExtras import QWinTaskbarButton
from PyQt5.QtCore import Qt, QTimer, QSettings
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QBrush, QColor
from Crypto.Cipher import AES, DES3, PKCS1_OAEP, PKCS1_v1_5, ChaCha20_Poly1305
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Signature import pss
from skein import skein256, skein512, skein1024, StreamCipher
import psutil
import shutil
import errno
import hmac
import subprocess
import tempfile
import winreg
import time
import os
import sys
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f} Yi{suffix}"

def _safe_file_size_fmt(path: str) -> str:
    try:
        return sizeof_fmt(os.path.getsize(path))
    except OSError:
        return "—"

def format_exception_for_user(e: Exception, action: str = "Operacja") -> str:
    if isinstance(e, PermissionError):
        return f"Błąd: {action} - brak uprawnień (odczyt/zapis)."
    if isinstance(e, FileNotFoundError):
        return f"Błąd: {action} - nie znaleziono pliku."
    if isinstance(e, MemoryError):
        return f"Błąd: {action} - niewystarczająca pamięć RAM."
    if isinstance(e, OSError) and getattr(e, "errno", None) in (errno.ENOSPC, errno.EDQUOT):
        return f"Błąd: {action} - brak miejsca na dysku."
    
    msg = str(e).strip()
    if not msg:
        msg = e.__class__.__name__

    if msg.startswith("Błąd:"):
        return msg
    
    return f"Błąd: {action} - {msg}"

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

def _is_ssd_windows(path):
    try:
        if not path or path.startswith(r"\\"):
            return False

        drive_letter = os.path.splitdrive(os.path.abspath(path))[0].rstrip(":\\").upper()
        if not drive_letter:
            return False

        ps_cmd = (
            f"$p = Get-Partition -DriveLetter '{drive_letter}' -ErrorAction SilentlyContinue; "
            "if ($p) { "
            "  $d = Get-Disk -Number $p.DiskNumber -ErrorAction SilentlyContinue; "
            "  if ($d) { "
            "    $mt = ($d.MediaType -as [string]); $bt = ($d.BusType -as [string]); "
            "    if ($mt -and $mt -ne 'Unspecified') { $mt } "
            "    elseif ($bt -and $bt -eq 'NVMe') { 'SSD' } "
            "    else { '' } "
            "  } else { '' } "
            "} else { '' }"
        )

        p = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                           capture_output=True, text=True, timeout=6)
        out = (p.stdout or "").strip()
        out_up = out.upper()

        if out_up:
            if "SSD" in out_up:
                return True
            if "HDD" in out_up:
                return False

        ps_cmd2 = (
            f"$p = Get-Partition -DriveLetter '{drive_letter}' -ErrorAction SilentlyContinue; "
            "if ($p) { $dn = $p.DiskNumber; "
            "  Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq $dn -or $_.FriendlyName -match $dn } | Select-Object -First 1 | ForEach-Object { $_.MediaType } "
            "} else { '' }"
        )
        p2 = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd2],
                            capture_output=True, text=True, timeout=6)
        out2 = (p2.stdout or "").strip().upper()
        if out2:
            if "SSD" in out2:
                return True
            if "HDD" in out2:
                return False

        ps_cmd3 = (
            f"$p = Get-Partition -DriveLetter '{drive_letter}' -ErrorAction SilentlyContinue; "
            "if ($p) { $idx = $p.DiskNumber; "
            "  $w = Get-WmiObject Win32_DiskDrive | Where-Object { $_.Index -eq $idx } | Select-Object -First 1; "
            "  if ($w) { $w.Model } else { '' } } else { '' }"
        )
        p3 = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd3],
                            capture_output=True, text=True, timeout=6)
        model = (p3.stdout or "").strip().upper()
        if model:
            if any(k in model for k in ("SSD", "NVME", "SOLID")):
                return True

        return False
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def _streaming_encrypt_aes_gcm(src_path, dst_path, key, chunk_size=1024*1024):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
        fout.write(nonce)
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            fout.write(cipher.encrypt(chunk))
        fout.write(cipher.digest())
        fout.flush()
        os.fsync(fout.fileno())

def _overwrite_with_random(path, chunk_size=4*1024*1024):
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.seek(0)
        remaining = size
        while remaining > 0:
            to_write = min(chunk_size, remaining)
            f.write(get_random_bytes(to_write))
            remaining -= to_write
        f.flush()
        os.fsync(f.fileno())

def _hybrid_crypto_erase(path, chunk_size=1024*1024, passes_for_hdd_overwrite=2, do_retrim=True):
    if not os.path.exists(path):
        return False, "Plik nie istnieje"
    dirn = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix="enc_tmp_", dir=dirn)
    os.close(fd)
    key = get_random_bytes(32)
    try:
        _streaming_encrypt_aes_gcm(path, tmp_path, key, chunk_size=chunk_size)

        try:
            kb = bytearray(key)
            for i in range(len(kb)):
                kb[i] = 0
            del kb
        except Exception:
            pass
        del key

        ssd = _is_ssd_windows(path)
        if not ssd:
            for _ in range(max(1, passes_for_hdd_overwrite)):
                _overwrite_with_random(path)

        os.replace(tmp_path, path)
        os.remove(path)

        if ssd and do_retrim:
            drive = os.path.splitdrive(os.path.abspath(path))[0].rstrip(":\\").upper()
            try:
                ps_cmd = (
                    f"Start-Process powershell -Verb RunAs -ArgumentList "
                    f"'-NoProfile -NoExit -Command \"Optimize-Volume -DriveLetter {drive} -ReTrim -Verbose\"'"
                )
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
            except Exception:
                pass

        return True, "Crypto-erase zakończony"
    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False, f"Błąd: {e}"

class EncryptDecryptThread(QThread):
    progress_signal = pyqtSignal(int, int, float)
    finished_signal = pyqtSignal(str)

    def __init__(self, file_path, key_path, public_key_path, algorithm, mode, padding, key_size, decrypt=False, save_path=None):
        super().__init__()
        self.file_path = file_path
        self.key_path = key_path
        self.public_key_path = public_key_path
        self.algorithm = algorithm
        self.mode = mode
        self.padding = padding
        self.key_size = key_size
        self.decrypt = decrypt
        self.save_path = save_path
        self._stop_requested = False
        self._ram_samples_count = 0
        self._ram_sum_mb = 0.0

    def request_stop(self):
        self._stop_requested = True

    def emit_progress(self, processed_size, file_size, progress):
        try:
            elapsed = time.time() - getattr(self, "_start_time", time.time())
            if elapsed > 0 and file_size > 0:
                rate = processed_size / elapsed
                remaining = max(0, file_size - processed_size)
                eta = int(remaining / rate) if rate > 0 else -1
            else:
                eta = -1
            proc = psutil.Process(os.getpid())
            rss_bytes = proc.memory_info().rss
            rss_mb = rss_bytes / (1024 * 1024)
            self._ram_samples_count += 1
            self._ram_sum_mb += rss_mb
            avg_ram_mb = self._ram_sum_mb / self._ram_samples_count
        except Exception:
            eta = -1
            avg_ram_mb = self._ram_sum_mb / max(1, self._ram_samples_count)
        self.progress_signal.emit(int(progress), int(eta), float(avg_ram_mb))

    def run(self):
        try:
            self._start_time = time.time()

            if getattr(self, "_stop_requested", False):
                self.finished_signal.emit("Info: Operacja została anulowana.")
                return

            file_size = os.path.getsize(self.file_path)
            processed_size = 0
            chunk_size = 1 * 1024 * 1024

            with open(self.file_path, "rb") as f:
                data = f.read()

            if self.algorithm == "AES":
                with open(self.key_path, "rb") as f:
                    key = f.read()

                if getattr(self, "_stop_requested", False):
                    self.finished_signal.emit("Info: Operacja została anulowana.")
                    return
                
                if len(key) != self.key_size//8 or len(key) not in (16, 24, 32):
                    raise ValueError("Błąd: Nieprawidłowa długość klucza! Wymagany klucz " + str(self.key_size) + "-bitowy, a podany klucz jest długości " + str(len(key) * 8) + " bitów.")

                if self.decrypt:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return
                    
                    if self.mode == "GCM (AEAD)":
                        if len(data) < 12 + 16:
                            raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                        nonce, tag, ciphertext = data[:12], data[-16:], data[12:-16]
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

                        decrypted_chunks = []
                        for i in range(0, len(ciphertext), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_chunks.append(cipher.decrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        try:
                            cipher.verify(tag)
                        except ValueError:
                            raise ValueError("Błąd: Nie udało się zweryfikować tagu MAC!")
                        
                        decrypted_data = b"".join(decrypted_chunks)
                        operation_message = "Sukces: Plik został deszyfrowany!"

                    elif self.mode == "EAX (AEAD)":
                        if len(data) < 16 + 16:
                            raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
                        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

                        decrypted_chunks = []
                        for i in range(0, len(ciphertext), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_chunks.append(cipher.decrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        try:
                            cipher.verify(tag)
                        except ValueError:
                            raise ValueError("Błąd: Nie udało się zweryfikować tagu MAC!")
                        
                        decrypted_data = b"".join(decrypted_chunks)
                        operation_message = "Sukces: Plik został deszyfrowany!"

                    elif self.mode == "CBC":
                        iv, ciphertext = data[:16], data[16:]
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

                        if len(data) < 16 + 16:
                            raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                        if len(ciphertext) % 16 != 0:
                            raise ValueError("Błąd: Uszkodzony format CBC!")

                        decrypted_chunks = []
                        for i in range(0, len(ciphertext), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_chunks.append(cipher.decrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        decrypted_data = b"".join(decrypted_chunks)
                        pad = decrypted_data[-1]
                        if pad < 1 or pad > 16 or decrypted_data[-pad:] != bytes([pad]) * pad:
                            raise ValueError("Błąd: Nieprawidłowy padding!")
                        decrypted_data = decrypted_data[:-pad]
                        operation_message = "Sukces: Plik został deszyfrowany!"

                    elif self.mode == "ECB":
                        ciphertext = data
                        cipher = AES.new(key, AES.MODE_ECB)

                        if len(ciphertext) < 16:
                            raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                        if len(ciphertext) % 16 != 0:
                            raise ValueError("Błąd: Uszkodzony format ECB!")
                        
                        decrypted_chunks = []
                        for i in range(0, len(ciphertext), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_chunks.append(cipher.decrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        decrypted_data = b"".join(decrypted_chunks)
                        pad = decrypted_data[-1]
                        if pad < 1 or pad > 16 or decrypted_data[-pad:] != bytes([pad]) * pad:
                            raise ValueError("Błąd: Nieprawidłowy padding!")
                        decrypted_data = decrypted_data[:-pad]
                        operation_message = "Sukces: Plik został deszyfrowany!"
                else:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return

                    if self.mode == "GCM (AEAD)":
                        nonce = get_random_bytes(12)
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

                        encrypted_chunks = []
                        for i in range(0, len(data), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = data[i:i + chunk_size]
                            encrypted_chunks.append(cipher.encrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        encrypted_data = nonce + b"".join(encrypted_chunks) + cipher.digest()
                        operation_message = "Sukces: Plik został zaszyfrowany!"

                    elif self.mode == "EAX (AEAD)":
                        nonce = get_random_bytes(16)
                        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

                        encrypted_chunks = []
                        for i in range(0, len(data), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = data[i:i + chunk_size]
                            encrypted_chunks.append(cipher.encrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        encrypted_data = nonce + cipher.digest() + b"".join(encrypted_chunks)
                        operation_message = "Sukces: Plik został zaszyfrowany!"

                    elif self.mode == "CBC":
                        iv = get_random_bytes(16)
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        padding_length = 16 - (len(data) % 16)
                        data += bytes([padding_length]) * padding_length

                        encrypted_chunks = []
                        for i in range(0, len(data), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = data[i:i + chunk_size]
                            encrypted_chunks.append(cipher.encrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        encrypted_data = iv + b"".join(encrypted_chunks)
                        operation_message = "Sukces: Plik został zaszyfrowany!"

                    elif self.mode == "ECB":
                        cipher = AES.new(key, AES.MODE_ECB)
                        padding_length = 16 - (len(data) % 16)
                        data += bytes([padding_length]) * padding_length

                        encrypted_chunks = []
                        for i in range(0, len(data), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = data[i:i + chunk_size]
                            encrypted_chunks.append(cipher.encrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        encrypted_data = b"".join(encrypted_chunks)
                        operation_message = "Sukces: Plik został zaszyfrowany!"

            elif self.algorithm == "RSA-PSS":
                with open(self.key_path, "rb") as f:
                    priv = RSA.import_key(f.read())

                with open(self.public_key_path, "rb") as f:
                    pub = RSA.import_key(f.read())

                if getattr(self, "_stop_requested", False):
                    self.finished_signal.emit("Info: Operacja została anulowana.")
                    return
                
                if not priv.has_private():
                    raise ValueError("Błąd: Wybrany klucz nie jest kluczem prywatnym!")
                
                if pub.has_private():
                    raise ValueError("Błąd: Wybrany klucz nie jest kluczem publicznym!")

                k_pub = pub.size_in_bytes()
                k_priv = priv.size_in_bytes()

                if k_pub != k_priv:
                    raise ValueError("Błąd: Klucz publiczny i prywatny mają różne rozmiary!")
                
                k = k_pub

                if k*8 != self.key_size or k*8 not in (1024, 2048, 3072, 4096):
                    raise ValueError("Błąd: Nieprawidłowa długość klucza! Wymagany klucz " + str(self.key_size) + "-bitowy, a podany klucz jest długości " + str(k*8) + " bitów.")

                if self.padding == "OAEP":
                    enc_cipher = PKCS1_OAEP.new(pub)
                    dec_cipher = PKCS1_OAEP.new(priv)
                    chunk_size = k - 42
                elif self.padding == "PKCS#1 v1.5":
                    enc_cipher = PKCS1_v1_5.new(pub)
                    dec_cipher = PKCS1_v1_5.new(priv)
                    chunk_size = k - 11

                if self.decrypt:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return

                    if len(data) < k:
                        raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                    signature = data[:k]
                    encrypted_data = data[k:]

                    if len(encrypted_data) % k != 0:
                        raise ValueError("Błąd: Integralność pliku nie została zachowana!")

                    h = SHA256.new(encrypted_data)
                    verifier = pss.new(pub)
                    try:
                        verifier.verify(h, signature)
                    except (ValueError, TypeError):
                        raise ValueError("Błąd: Nie udało się zweryfikować podpisu PSS!")

                    decrypted_chunks = []
                    for i in range(0, len(encrypted_data), k):
                        if getattr(self, "_stop_requested", False):
                            self.finished_signal.emit("Info: Operacja została anulowana.")
                            return

                        chunk = encrypted_data[i:i + k]

                        if self.padding == "PKCS#1 v1.5":
                            sentinel = b"ERROR"
                            pt = dec_cipher.decrypt(chunk, sentinel)
                            if pt == sentinel:
                                raise ValueError("Błąd: Uszkodzony plik!")
                            
                        elif self.padding == "OAEP":
                            try:
                                pt = dec_cipher.decrypt(chunk)
                            except ValueError:
                                raise ValueError("Błąd: Uszkodzony plik!")
                            
                        decrypted_chunks.append(pt)
                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.emit_progress(processed_size, file_size, progress)

                    decrypted_data = b"".join(decrypted_chunks)
                    operation_message = "Sukces: Plik został deszyfrowany!"
                else:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return

                    encrypted_chunks = []
                    for i in range(0, len(data), chunk_size):
                        if getattr(self, "_stop_requested", False):
                            self.finished_signal.emit("Info: Operacja została anulowana.")
                            return

                        chunk = data[i:i + chunk_size]
                        encrypted_chunks.append(enc_cipher.encrypt(chunk))
                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.emit_progress(processed_size, file_size, progress)

                    encrypted_data = b"".join(encrypted_chunks)
                    h = SHA256.new(encrypted_data)
                    signer = pss.new(priv)
                    signature = signer.sign(h)

                    encrypted_data = signature + encrypted_data
                    operation_message = "Sukces: Plik został zaszyfrowany!"

            elif self.algorithm == "3DES":
                with open(self.key_path, "rb") as f:
                    key = f.read()

                if getattr(self, "_stop_requested", False):
                    self.finished_signal.emit("Info: Operacja została anulowana.")
                    return

                if len(key) != 24:
                    raise ValueError("Błąd: Nieprawidłowa długość klucza 3DES! Użyj klucza 192-bitowego.")
                
                if self.decrypt:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return

                    if self.mode == "EAX (AEAD)":
                        if len(data) < 16 + 16:
                            raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                        nonce, tag, ciphertext = data[:16], data[16:24], data[24:]
                        cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce, mac_len=8)

                        decrypted_chunks = []
                        for i in range(0, len(ciphertext), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_chunks.append(cipher.decrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        try:
                            cipher.verify(tag)
                        except ValueError:
                            raise ValueError("Błąd: Nie udało się zweryfikować tagu MAC!")
                        decrypted_data = b"".join(decrypted_chunks)
                        operation_message = "Sukces: Plik został deszyfrowany!"
                        
                    elif self.mode == "CFB":
                        if len(data) < 8:
                            raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                        iv, ciphertext = data[:8], data[8:]
                        cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)

                        decrypted_chunks = []
                        for i in range(0, len(ciphertext), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_chunks.append(cipher.decrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        decrypted_data = b"".join(decrypted_chunks)
                        operation_message = "Sukces: Plik został deszyfrowany!"

                    elif self.mode == "OFB":
                        if len(data) < 8:
                            raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                        iv, ciphertext = data[:8], data[8:]
                        cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)

                        decrypted_chunks = []
                        for i in range(0, len(ciphertext), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_chunks.append(cipher.decrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        decrypted_data = b"".join(decrypted_chunks)
                        operation_message = "Sukces: Plik został deszyfrowany!"
                else:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return

                    if self.mode == "EAX (AEAD)":
                        cipher = DES3.new(key, DES3.MODE_EAX, mac_len=8)

                        encrypted_chunks = []
                        for i in range(0, len(data), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = data[i:i + chunk_size]
                            encrypted_chunks.append(cipher.encrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        encrypted_data = cipher.nonce + cipher.digest() + b"".join(encrypted_chunks)
                        operation_message = "Sukces: Plik został zaszyfrowany!"

                    elif self.mode == "CFB":
                        iv = get_random_bytes(8)
                        cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)
                        encrypted_data = iv

                        encrypted_chunks = []
                        for i in range(0, len(data), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = data[i:i + chunk_size]
                            encrypted_chunks.append(cipher.encrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        encrypted_data += b"".join(encrypted_chunks)
                        operation_message = "Sukces: Plik został zaszyfrowany!"

                    elif self.mode == "OFB":
                        iv = get_random_bytes(8)
                        cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
                        encrypted_data = iv

                        encrypted_chunks = []
                        for i in range(0, len(data), chunk_size):
                            if getattr(self, "_stop_requested", False):
                                self.finished_signal.emit("Info: Operacja została anulowana.")
                                return

                            chunk = data[i:i + chunk_size]
                            encrypted_chunks.append(cipher.encrypt(chunk))
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.emit_progress(processed_size, file_size, progress)
                        encrypted_data += b"".join(encrypted_chunks)
                        operation_message = "Sukces: Plik został zaszyfrowany!"

            elif self.algorithm == "XChaCha20-Poly1305":
                with open(self.key_path, "rb") as f:
                    key = f.read()

                if getattr(self, "_stop_requested", False):
                    self.finished_signal.emit("Info: Operacja została anulowana.")
                    return

                if len(key) != 32:
                    raise ValueError("Błąd: Nieprawidłowa długość klucza XChaCha20-Poly1305! Użyj klucza 256-bitowego.")
                
                if self.decrypt:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return
                    
                    if len(data) < 24 + 16:
                        raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")

                    nonce, tag, ciphertext = data[:24], data[-16:], data[24:-16]
                    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                    
                    decrypted_chunks = []
                    for i in range(0, len(ciphertext), chunk_size):
                        if getattr(self, "_stop_requested", False):
                            self.finished_signal.emit("Info: Operacja została anulowana.")
                            return

                        decrypted_chunks.append(cipher.decrypt(ciphertext[i:i + chunk_size]))
                        processed_size += len(ciphertext[i:i + chunk_size])
                        progress = int((processed_size / file_size) * 100)
                        self.emit_progress(processed_size, file_size, progress)
                    try:
                        cipher.verify(tag)
                    except ValueError:
                        raise ValueError("Błąd: Nie udało się zweryfikować tagu Poly1305!")
                    
                    decrypted_data = b"".join(decrypted_chunks)
                    operation_message = "Sukces: Plik został deszyfrowany!"
                else:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return

                    nonce = get_random_bytes(24)
                    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

                    encrypted_chunks = []
                    for i in range(0, len(data), chunk_size):
                        if getattr(self, "_stop_requested", False):
                            self.finished_signal.emit("Info: Operacja została anulowana.")
                            return

                        chunk = data[i:i + chunk_size]
                        encrypted_chunks.append(cipher.encrypt(chunk))
                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.emit_progress(processed_size, file_size, progress)
                    tag = cipher.digest()
                    encrypted_data = nonce + b"".join(encrypted_chunks) + tag
                    operation_message = "Sukces: Plik został zaszyfrowany!"
                    
            elif self.algorithm == "Threefish-Skein-MAC":
                def derive_subkeys(master_key: bytes, nonce: bytes):
                    key_len = len(master_key)
                    info = b"Threefish-Skein-MAC|v1|" + str(key_len * 8).encode()
                    okm = HKDF(master_key, 2 * key_len, salt=nonce, hashmod=SHA256, context=info)
                    return okm[:key_len], okm[key_len:]

                with open(self.key_path, "rb") as f:
                    key = f.read()

                if getattr(self, "_stop_requested", False):
                    self.finished_signal.emit("Info: Operacja została anulowana.")
                    return

                if len(key) != self.key_size//8 or len(key) not in (32, 64, 128):
                    raise ValueError("Błąd: Nieprawidłowa długość klucza! Wymagany klucz " + str(self.key_size) + "-bitowy, a podany klucz jest długości " + str(len(key) * 8) + " bitów.")
                
                if self.decrypt:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return

                    if len(key) == 32:
                        hash_func = skein256
                        tag_size = 32
                    elif len(key) == 64:
                        hash_func = skein512
                        tag_size = 64
                    else:
                        hash_func = skein1024
                        tag_size = 128

                    if len(data) < 16 + tag_size:
                        raise ValueError("Błąd: Zaszyfrowany plik jest zbyt krótki lub uszkodzony!")
                        
                    nonce, tag, ciphertext = data[:16], data[-tag_size:], data[16:-tag_size]
                    enc_key, mac_key = derive_subkeys(key, nonce)

                    aad = b"Threefish-Skein-MAC|v1|" + str(len(key)*8).encode() + b"|"
                    tag_input = aad + nonce + ciphertext
                    calculated_tag = hash_func(tag_input, key=mac_key).digest()
                    if not hmac.compare_digest(calculated_tag, tag):
                        raise ValueError("Błąd: Nie udało się zweryfikować tagu Skein-MAC!")

                    sc = StreamCipher(key=enc_key, nonce=nonce, hasher=hash_func)

                    cipher_chunks = []
                    for i in range(0, len(ciphertext), chunk_size):
                        if getattr(self, "_stop_requested", False):
                            self.finished_signal.emit("Info: Operacja została anulowana.")
                            return

                        chunk = ciphertext[i:i+chunk_size]
                        cipher_chunks.append(sc.decrypt(chunk))

                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.emit_progress(processed_size, file_size, progress)

                    decrypted_data = b"".join(cipher_chunks) 
                    operation_message = "Sukces: Plik został deszyfrowany!"
                else:
                    if getattr(self, "_stop_requested", False):
                        self.finished_signal.emit("Info: Operacja została anulowana.")
                        return

                    if len(key) == 32:
                        hash_func = skein256
                    elif len(key) == 64:
                        hash_func = skein512
                    else:
                        hash_func = skein1024

                    nonce = get_random_bytes(16)
                    enc_key, mac_key = derive_subkeys(key, nonce)
                    
                    sc = StreamCipher(key=enc_key, nonce=nonce, hasher=hash_func)

                    encrypted_chunks = []
                    for i in range(0, len(data), chunk_size):
                        if getattr(self, "_stop_requested", False):
                            self.finished_signal.emit("Info: Operacja została anulowana.")
                            return

                        chunk = data[i:i+chunk_size]
                        encrypted_chunks.append(sc.encrypt(chunk))

                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.emit_progress(processed_size, file_size, progress)

                    ciphertext = b"".join(encrypted_chunks)
                        
                    aad = b"Threefish-Skein-MAC|v1|" + str(len(key)*8).encode() + b"|"
                    tag_input = aad + nonce + ciphertext
                    tag = hash_func(tag_input, key=mac_key).digest()

                    encrypted_data = nonce + ciphertext + tag
                    operation_message = "Sukces: Plik został zaszyfrowany!"

            if self.decrypt:
                if getattr(self, "_stop_requested", False):
                    self.finished_signal.emit("Info: Operacja została anulowana.")
                    return

                dec_path = self.save_path if self.save_path else self.file_path.replace(".enc", ".dec")
                atomic_write_bytes(dec_path, decrypted_data)
            else:
                if getattr(self, "_stop_requested", False):
                    self.finished_signal.emit("Info: Operacja została anulowana.")
                    return

                enc_path = self.save_path if self.save_path else self.file_path + ".enc"
                atomic_write_bytes(enc_path, encrypted_data)

            self.progress_signal.emit(100, 0, self._ram_sum_mb / max(1, self._ram_samples_count))
            try:
                elapsed = int(time.time() - getattr(self, "_start_time", time.time()))
                h = elapsed // 3600
                m = (elapsed % 3600) // 60
                s = elapsed % 60
                avg_ram_mb = self._ram_sum_mb / max(1, self._ram_samples_count)
                if "zaszyfrowany" in operation_message or "deszyfrowany" in operation_message:
                    operation_message = f"{operation_message} (czas: {h:02d}:{m:02d}:{s:02d}, średnie użycie RAM: {avg_ram_mb:.2f} MB)"
            except Exception:
                pass
            self.finished_signal.emit(operation_message)

        except Exception as e:
            self.finished_signal.emit(format_exception_for_user(e))

class FileLabel(QLabel):
    def __init__(self, parent=None, file_type=0):
        super().__init__(parent)
        self.file_type = file_type
        if file_type == 0:
            self.setText("Przeciągnij tutaj lub wybierz plik")
        elif file_type == 1:
            self.setText("Przeciągnij tutaj lub wybierz klucz")
        elif file_type == 2:
            self.setText("Przeciągnij tutaj lub wybierz klucz prywatny")
        elif file_type == 3:
            self.setText("Przeciągnij tutaj lub wybierz klucz publiczny")
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.file_path = ""

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            main_window = self.window()
            if self.file_type == 0:
                path_to_open = self.file_path
            elif self.file_type == 1:
                path_to_open = main_window.key_path
            elif self.file_type == 2:
                path_to_open = main_window.private_key_path
            elif self.file_type == 3:
                path_to_open = main_window.public_key_path

            if path_to_open and os.path.exists(path_to_open):
                path_to_open = os.path.normpath(path_to_open)
                subprocess.Popen(f'explorer /select,"{path_to_open}"')
        else:
            super().mouseDoubleClickEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.reset_style()
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.reset_style()

    def reset_style(self):
        main_window = self.window()
        theme_mode = "dark"

        if main_window is not None and hasattr(main_window, "settings"):
            theme_mode = main_window.settings.value("theme_mode", "dark")

        self.setProperty("theme_mode", theme_mode)

        try:
            self.style().unpolish(self)
            self.style().polish(self)
            self.update()
        except Exception:
            pass

    def dropEvent(self, event):
        self.reset_style()
        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            self.file_path = urls[0].toLocalFile()
            if self.file_type == 0:
                self.setText(f"Plik: {self.file_path}")
            elif self.file_type == 1:
                self.setText(f"Klucz: {self.file_path}")
            elif self.file_type == 2:
                self.setText(f"Klucz prywatny: {self.file_path}")
            elif self.file_type == 3:
                self.setText(f"Klucz publiczny: {self.file_path}")
            self.setToolTip("Ścieżka: " + self.file_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.file_path))
            main_window = self.window()
            if self.file_type == 0:
                main_window.file_path = self.file_path
                main_window.clear_file_button.setEnabled(True)
                main_window._add_to_history(self.file_path, main_window.recent_files)
                main_window._update_recent_files_menu()
                main_window.settings.setValue("recent_files", main_window.recent_files)
            elif self.file_type == 1:
                main_window.key_path = self.file_path
                main_window.clear_key_button.setEnabled(True)
                main_window._add_to_history(self.file_path, main_window.recent_keys)
                main_window._update_recent_keys_menu()
                main_window.settings.setValue("recent_keys", main_window.recent_keys)
            elif self.file_type == 2:
                main_window.private_key_path = self.file_path
                main_window.clear_private_key_button.setEnabled(True)
                main_window._add_to_history(self.file_path, main_window.recent_private_keys)
                main_window._update_recent_private_keys_menu()
                main_window.settings.setValue("recent_private_keys", main_window.recent_private_keys)
            elif self.file_type == 3:
                main_window.public_key_path = self.file_path
                main_window.clear_public_key_button.setEnabled(True)
                main_window._add_to_history(self.file_path, main_window.recent_public_keys)
                main_window._update_recent_public_keys_menu()
                main_window.settings.setValue("recent_public_keys", main_window.recent_public_keys)

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        icon_path = os.path.join(application_path, "assets", "icon.ico")
        self.setWindowIcon(QIcon(icon_path))
        self.settings = QSettings("Vyroxes", "Szyfrowanie i deszyfrowanie plików")
        self.recent_files = self.settings.value("recent_files", [], type=list)
        self.recent_keys = self.settings.value("recent_keys", [], type=list)
        self.recent_private_keys = self.settings.value("recent_private_keys", [], type=list)
        self.recent_public_keys = self.settings.value("recent_public_keys", [], type=list)
        self.init_ui()
        self._update_recent_files_menu()
        self._update_recent_keys_menu()
        self._update_recent_private_keys_menu()
        self._update_recent_public_keys_menu()
        self.taskbar_button = None
        self.taskbar_progress = None

    def init_ui(self):
        self.dark_stylesheet = """
            QWidget {
                background-color: #2e2e2e;
                color: #ffffff;
                font-family: Arial, sans-serif;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                padding: 5px;
                font-size: 14px;
            }
            QLabel[filelabel="true"] {
                border: 2px dashed #5c6062;
                padding: 10px;
            }
            QLabel[filelabel="true"]:hover {
                background-color: #4c5052;
            }
            QPushButton:hover {
                background-color: #4c5052;
            }
            QPushButton:pressed {
                background-color: #5c6062;
            }
            QComboBox {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                padding: 3px;
                font-size: 14px;
                padding-left: 6px;
            }
            QComboBox:hover {
                background-color: #4c5052;
            }
            QComboBox QAbstractItemView {
                background-color: #3c3f41;
                color: #ffffff;
                selection-background-color: #4c5052;
                padding: 3px;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                padding: 10px;
                font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px;
                color: #ffffff;
            }
            QProgressBar {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                text-align: center;
                font-size: 14px;
            }
            QProgressBar::chunk {
                background-color: #4caf50;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #6e6e6e;
                background-color: #3c3f41;
                border-radius: 3px;
            }
            QCheckBox::indicator:hover {
                background-color: #4c5052;
                border: 1px solid #9aa0a0;
            }
            QCheckBox::indicator:checked {
                background-color: #6ab04c;
                border: 1px solid #3f692d;
            }
            QCheckBox::indicator:checked:hover {
                background-color: #84ca66;
                border: 1px solid #a5d092;
            }
        """

        self.light_stylesheet = """
            QWidget {
                background-color: #ffffff;
                color: #000000;
                font-family: Arial, sans-serif;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton {
                background-color: #f0f0f0;
                color: #000000;
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                padding: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }
            QLabel[filelabel="true"] {
                border: 2px dashed #d0d0d0;
                padding: 10px;
            }
            QLabel[filelabel="true"]:hover {
                background-color: #f0f0f0;
            }
            QComboBox {
                background-color: #f0f0f0;
                color: #000000;
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                padding: 3px;
                font-size: 14px;
                padding-left: 6px;
            }
            QComboBox:hover {
                background-color: #e0e0e0;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                color: #000000;
                selection-background-color: #d0d0d0;
                padding: 3px;
            }
            QGroupBox {
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                margin-top: 10px;
                padding: 10px;
                font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px;
                color: #000000;
            }
            QProgressBar {
                background-color: #f0f0f0;
                color: #000000;
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                text-align: center;
                font-size: 14px;
            }
            QProgressBar::chunk {
                background-color: #4caf50;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #c0c0c0;
                background-color: #f0f0f0;
                border-radius: 3px;
            }
            QCheckBox::indicator:hover {
                background-color: #e0e0e0;
            }
            QCheckBox::indicator:checked {
                background-color: #6ab04c;
                border: 1px solid #558c3d;
            }
            QCheckBox::indicator:checked:hover {
                background-color: #84ca66;
                border: 1px solid #a5d092;
            }
        """

        auto_theme = self.settings.value("auto_theme", True, type=bool)
        theme_mode = self.settings.value("theme_mode", "dark")

        self.system_theme_timer = QTimer(self)
        self.system_theme_timer.setInterval(1000)
        self.system_theme_timer.timeout.connect(self.on_system_theme_check)

        if auto_theme:
            self._apply_system_theme()
            self.system_theme_timer.start()
        else:
            if theme_mode == "light":
                self._apply_light_theme()
            else:
                self._apply_dark_theme()

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)

        theme_group = QGroupBox("Motyw")
        theme_layout = QHBoxLayout()
        self.auto_theme_checkbox = QCheckBox("Automatycznie (motyw systemowy)")
        self.auto_theme_checkbox.setChecked(self.settings.value("auto_theme", True, type=bool))
        self.auto_theme_checkbox.stateChanged.connect(self.on_auto_theme_changed)
        theme_layout.addWidget(self.auto_theme_checkbox)
        self.light_theme_button = QPushButton("Jasny")
        self.light_theme_button.clicked.connect(lambda: self.set_theme_mode("light"))
        theme_layout.addWidget(self.light_theme_button)
        self.dark_theme_button = QPushButton("Ciemny")
        self.dark_theme_button.clicked.connect(lambda: self.set_theme_mode("dark"))
        theme_layout.addWidget(self.dark_theme_button)
        self.on_auto_theme_changed(self.auto_theme_checkbox.checkState())
        theme_group.setLayout(theme_layout)
        main_layout.addWidget(theme_group)

        file_group = QGroupBox("Plik do szyfrowania/deszyfrowania")
        self.label = FileLabel(self, 0)
        self.label.setProperty("filelabel", "true")
        file_layout = QVBoxLayout()
        file_layout.addWidget(self.label)
        file_buttons_layout = QHBoxLayout()
        self.recent_files_button = QPushButton()
        self.recent_files_button.setFixedWidth(30)
        self.recent_files_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                border: 1px solid #dd343c;
            }
            QPushButton:hover {
                background-color: #f47570;
                border: 1px solid #e68e8b;
            }
        """)
        self.recent_files_menu = QMenu()
        for file in self.recent_files:
            action = self.recent_files_menu.addAction(file)
            action.triggered.connect(lambda checked, p=file: self.select_recent_file(p))
        self.recent_files_button.setMenu(self.recent_files_menu)
        file_buttons_layout.addWidget(self.recent_files_button)
        self.file_button = QPushButton("Wybierz plik")
        self.file_button.clicked.connect(self.select_file)
        file_buttons_layout.addWidget(self.file_button)
        self.clear_file_button = QPushButton("X")
        self.clear_file_button.setFixedWidth(30)
        self.clear_file_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                border: 1px solid #dd343c;
            }
            QPushButton:hover {
                background-color: #ff7777;
                border: 1px solid #e68e8b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                border: 1px solid #555555;
                color: #666666;
            }
        """)
        self.clear_file_button.clicked.connect(self.clear_file_path)
        self.clear_file_button.setEnabled(False)
        file_buttons_layout.addWidget(self.clear_file_button)
        file_layout.addLayout(file_buttons_layout)
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        algo_group = QGroupBox("Algorytm")
        algo_layout = QVBoxLayout()
        self.algorithm_box = QComboBox()
        items = [
            ("--- Symetryczne ---", None),
            ("AES", "AES"),
            ("3DES", "3DES"),
            ("XChaCha20-Poly1305", "XChaCha20-Poly1305"),
            ("Threefish-Skein-MAC", "Threefish-Skein-MAC"),
            ("--- Asymetryczne ---", None),
            ("RSA-PSS", "RSA-PSS"),
        ]

        self.algorithm_box.clear()
        previous_index = 1

        for text, value in items:
            self.algorithm_box.addItem(text, value)
            if value is None:
                index = self.algorithm_box.count() - 1
                item = self.algorithm_box.model().item(index)
                item.setFlags(Qt.NoItemFlags)
                item.setForeground(QBrush(QColor("gray")))
                
        self.algorithm_box.setCurrentIndex(previous_index)
        self.algorithm_box.currentIndexChanged.connect(self.update_algorithm_settings)

        algo_layout.addWidget(self.algorithm_box)
        self.additional_options_button = QPushButton("Ustawienia algorytmu ▼")
        self.additional_options_button.clicked.connect(self.toggle_additional_options)
        algo_layout.addWidget(self.additional_options_button)

        self.additional_options_widget = QWidget()
        additional_options_layout = QVBoxLayout()

        # opcje AES
        self.aes_options_widget = QWidget()
        aes_options_layout = QVBoxLayout()
        self.aes_key_size_label = QLabel("Wybierz długość klucza (bit):")
        aes_options_layout.addWidget(self.aes_key_size_label)
        self.aes_key_size_box = QComboBox()
        self.aes_key_size_box.addItems(["128", "192", "256"])
        self.aes_key_size_box.setCurrentIndex(2)
        aes_options_layout.addWidget(self.aes_key_size_box)
        self.aes_mode_label = QLabel("Wybierz tryb pracy:")
        aes_options_layout.addWidget(self.aes_mode_label)
        self.aes_mode_box = QComboBox()
        self.aes_mode_box.addItems(["GCM (AEAD)", "EAX (AEAD)", "CBC", "ECB"])
        aes_options_layout.addWidget(self.aes_mode_box)
        self.aes_options_widget.setLayout(aes_options_layout)
        additional_options_layout.addWidget(self.aes_options_widget)

        # opcje RSA-PSS
        self.rsa_options_widget = QWidget()
        rsa_options_layout = QVBoxLayout()
        self.rsa_key_size_label = QLabel("Wybierz długość kluczy (bit):")
        rsa_options_layout.addWidget(self.rsa_key_size_label)
        self.rsa_key_size_box = QComboBox()
        self.rsa_key_size_box.addItems(["1024", "2048", "3072"])
        self.rsa_key_size_box.setCurrentIndex(2)
        rsa_options_layout.addWidget(self.rsa_key_size_box)
        self.rsa_padding_label = QLabel("Wybierz padding:")
        rsa_options_layout.addWidget(self.rsa_padding_label)
        self.rsa_padding_box = QComboBox()
        self.rsa_padding_box.addItems(["PKCS#1 v1.5", "OAEP"])
        self.rsa_padding_box.setCurrentIndex(1)
        rsa_options_layout.addWidget(self.rsa_padding_box)
        self.rsa_options_widget.setLayout(rsa_options_layout)
        additional_options_layout.addWidget(self.rsa_options_widget)
        self.rsa_options_widget.setVisible(False)

        # opcje 3DES
        self.des_options_widget = QWidget()
        des_options_layout = QVBoxLayout()
        self.des_mode_label = QLabel("Wybierz tryb pracy:")
        des_options_layout.addWidget(self.des_mode_label)
        self.des_mode_box = QComboBox()
        self.des_mode_box.addItems(["EAX (AEAD)", "CFB", "OFB"])
        des_options_layout.addWidget(self.des_mode_box)
        self.des_options_widget.setLayout(des_options_layout)
        additional_options_layout.addWidget(self.des_options_widget)
        self.des_options_widget.setVisible(False)

        # opcje Threefish-Skein-MAC
        self.threefish_options_widget = QWidget()
        threefish_options_layout = QVBoxLayout()
        self.threefish_key_size_label = QLabel("Wybierz długość klucza (bit):")
        threefish_options_layout.addWidget(self.threefish_key_size_label)
        self.threefish_key_size_box = QComboBox()
        self.threefish_key_size_box.addItems(["256", "512", "1024"])
        self.threefish_key_size_box.setCurrentIndex(2)
        threefish_options_layout.addWidget(self.threefish_key_size_box)
        self.threefish_options_widget.setLayout(threefish_options_layout)
        additional_options_layout.addWidget(self.threefish_options_widget)
        self.threefish_options_widget.setVisible(False)

        self.additional_options_widget.setLayout(additional_options_layout)
        self.additional_options_widget.setVisible(False)
        algo_layout.addWidget(self.additional_options_widget)
        algo_group.setLayout(algo_layout)
        main_layout.addWidget(algo_group)

        self.key_group = QGroupBox("Klucz")
        self.key_layout = QVBoxLayout()
        self.key_label = FileLabel(self, 1)
        self.key_label.setProperty("filelabel", "true")
        key_buttons_layout = QHBoxLayout()
        self.recent_keys_button = QPushButton()
        self.recent_keys_button.setFixedWidth(30)
        self.recent_keys_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                border: 1px solid #dd343c;
            }
            QPushButton:hover {
                background-color: #f47570;
                border: 1px solid #e68e8b;
            }
        """)
        self.recent_keys_menu = QMenu()
        for key in self.recent_keys:
            action = self.recent_keys_menu.addAction(key)
            action.triggered.connect(lambda checked, p=key: self.select_recent_key(p))
        self.recent_keys_button.setMenu(self.recent_keys_menu)
        key_buttons_layout.addWidget(self.recent_keys_button)
        self.key_layout.addWidget(self.key_label)
        self.key_button = QPushButton("Wybierz klucz")
        self.key_button.clicked.connect(self.select_key_file)
        key_buttons_layout.addWidget(self.key_button)
        self.clear_key_button = QPushButton("X")
        self.clear_key_button.setFixedWidth(30)
        self.clear_key_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                border: 1px solid #dd343c;
            }
            QPushButton:hover {
                background-color: #ff7777;
                border: 1px solid #e68e8b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                border: 1px solid #555555;
                color: #666666;
            }
        """)
        self.clear_key_button.clicked.connect(self.clear_key_path)
        self.clear_key_button.setEnabled(False)
        key_buttons_layout.addWidget(self.clear_key_button)
        self.key_layout.addLayout(key_buttons_layout)
        self.key_group.setLayout(self.key_layout)
        self.generate_key_button = QPushButton("Generuj klucz")
        self.generate_key_button.clicked.connect(self.generate_key)
        self.key_layout.addWidget(self.generate_key_button)

        self.rsa_key_widget = QWidget()
        rsa_key_layout = QVBoxLayout()
        self.rsa_private_key_label = FileLabel(self, 2)
        self.rsa_private_key_label.setProperty("filelabel", "true")
        rsa_key_layout.addWidget(self.rsa_private_key_label)
        private_key_buttons_layout = QHBoxLayout()
        self.recent_private_keys_button = QPushButton()
        self.recent_private_keys_button.setFixedWidth(30)
        self.recent_private_keys_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                border: 1px solid #dd343c;
            }
            QPushButton:hover {
                background-color: #f47570;
                border: 1px solid #e68e8b;
            }
        """)
        self.recent_private_keys_menu = QMenu()
        for key in self.recent_private_keys:
            action = self.recent_private_keys_menu.addAction(key)
            action.triggered.connect(lambda checked, p=key: self.select_recent_private_key(p))
        self.recent_private_keys_button.setMenu(self.recent_private_keys_menu)
        private_key_buttons_layout.addWidget(self.recent_private_keys_button)
        self.select_private_key_button = QPushButton("Wybierz klucz prywatny")
        self.select_private_key_button.clicked.connect(self.select_private_key_file)
        private_key_buttons_layout.addWidget(self.select_private_key_button)
        self.clear_private_key_button = QPushButton("X")
        self.clear_private_key_button.setFixedWidth(30)
        self.clear_private_key_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                border: 1px solid #dd343c;
            }
            QPushButton:hover {
                background-color: #ff7777;
                border: 1px solid #e68e8b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                border: 1px solid #555555;
                color: #666666;
            }
        """)
        self.clear_private_key_button.clicked.connect(self.clear_private_key_path)
        self.clear_private_key_button.setEnabled(False)
        private_key_buttons_layout.addWidget(self.clear_private_key_button)
        rsa_key_layout.addLayout(private_key_buttons_layout)
        self.generate_private_key_button = QPushButton("Generuj klucz prywatny")
        self.generate_private_key_button.clicked.connect(self.generate_private_key)
        rsa_key_layout.addWidget(self.generate_private_key_button)

        self.rsa_public_key_label = FileLabel(self, 3)
        self.rsa_public_key_label.setProperty("filelabel", "true")
        rsa_key_layout.addWidget(self.rsa_public_key_label)
        public_key_buttons_layout = QHBoxLayout()
        self.recent_public_keys_button = QPushButton()
        self.recent_public_keys_button.setFixedWidth(30)
        self.recent_public_keys_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                border: 1px solid #dd343c;
            }
            QPushButton:hover {
                background-color: #f47570;
                border: 1px solid #e68e8b;
            }
        """)
        self.recent_public_keys_menu = QMenu()
        for key in self.recent_public_keys:
            action = self.recent_public_keys_menu.addAction(key)
            action.triggered.connect(lambda checked, p=key: self.select_recent_public_key(p))
        self.recent_public_keys_button.setMenu(self.recent_public_keys_menu)
        public_key_buttons_layout.addWidget(self.recent_public_keys_button)
        self.select_public_key_button = QPushButton("Wybierz klucz publiczny")
        self.select_public_key_button.clicked.connect(self.select_public_key_file)
        public_key_buttons_layout.addWidget(self.select_public_key_button)
        self.clear_public_key_button = QPushButton("X")
        self.clear_public_key_button.setFixedWidth(30)
        self.clear_public_key_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                border: 1px solid #dd343c;
            }
            QPushButton:hover {
                background-color: #ff7777;
                border: 1px solid #e68e8b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                border: 1px solid #555555;
                color: #666666;
            }
        """)
        self.clear_public_key_button.clicked.connect(self.clear_public_key_path)
        self.clear_public_key_button.setEnabled(False)
        public_key_buttons_layout.addWidget(self.clear_public_key_button)
        rsa_key_layout.addLayout(public_key_buttons_layout)
        self.generate_public_key_button = QPushButton("Generuj klucz publiczny")
        self.generate_public_key_button.clicked.connect(self.generate_public_key)
        rsa_key_layout.addWidget(self.generate_public_key_button)
        self.rsa_key_widget.setLayout(rsa_key_layout)
        self.rsa_key_widget.setVisible(False)
        self.key_layout.addWidget(self.rsa_key_widget)
        self.key_group.setLayout(self.key_layout)
        main_layout.addWidget(self.key_group)

        ops_group = QGroupBox("Operacje")
        ops_layout = QVBoxLayout()
        encrypt_decrypt_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Szyfruj")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        encrypt_decrypt_layout.addWidget(self.encrypt_button)
        self.decrypt_button = QPushButton("Deszyfruj")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        encrypt_decrypt_layout.addWidget(self.decrypt_button)
        ops_layout.addLayout(encrypt_decrypt_layout)
        self.cancel_button = QPushButton("Anuluj")
        self.cancel_button.clicked.connect(self.cancel_operation)
        self.cancel_button.setVisible(False)
        ops_layout.addWidget(self.cancel_button)
        ops_group.setLayout(ops_layout)
        main_layout.addWidget(ops_group)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.progress_bar)

        self.algorithm_widgets = {
            "AES": [self.aes_options_widget],
            "RSA-PSS": [self.rsa_options_widget, self.rsa_key_widget],
            "3DES": [self.des_options_widget],
            "XChaCha20-Poly1305": [],
            "Threefish-Skein-MAC": [self.threefish_options_widget]
        }

        self.all_controls = [
            self.auto_theme_checkbox,
            self.light_theme_button,
            self.dark_theme_button,
            self.label,
            self.recent_files_button,
            self.file_button,
            self.clear_file_button,
            self.key_label,
            self.recent_keys_button,
            self.key_button,
            self.clear_key_button,
            self.generate_key_button,
            self.rsa_private_key_label,
            self.recent_private_keys_button,
            self.select_private_key_button,
            self.clear_private_key_button,
            self.generate_private_key_button,
            self.rsa_public_key_label,
            self.recent_public_keys_button,
            self.select_public_key_button,
            self.clear_public_key_button,
            self.generate_public_key_button,
            self.encrypt_button,
            self.decrypt_button,
            self.algorithm_box,
            self.additional_options_button,
            self.aes_key_size_box,
            self.aes_mode_box,
            self.rsa_key_size_box,
            self.rsa_padding_box,
            self.des_mode_box,
            self.threefish_key_size_box
        ]

        self.setLayout(main_layout)
        self.setWindowTitle("Szyfrowanie i deszyfrowanie plików")
        self.setMinimumWidth(500)
        self.setMaximumSize(self.sizeHint().width(), self.sizeHint().height())
        self.file_path = ""
        self.key_path = ""
        self.private_key_path = ""
        self.public_key_path = ""
        self.save_path = ""

    def clear_history(self, history_list, menu, type):
        history_list.clear()
        menu.clear()
        if type == 0:
            self.settings.setValue("recent_files", self.recent_files)
        elif type == 1:
            self.settings.setValue("recent_keys", self.recent_keys)
        elif type == 2:
            self.settings.setValue("recent_private_keys", self.recent_private_keys)
        elif type == 3:
            self.settings.setValue("recent_public_keys", self.recent_public_keys)
        self._add_menu_actions(type)

    def _add_menu_actions(self, type):
        if type == 0:
            clear_action = self.recent_files_menu.addAction("Wyczyść historię ostatnich plików")
            clear_action.triggered.connect(lambda: self.clear_history(self.recent_files, self.recent_files_menu, 0))
            self.recent_files_menu.addSeparator()
        elif type == 1:
            clear_action = self.recent_keys_menu.addAction("Wyczyść historię ostatnich kluczy")
            clear_action.triggered.connect(lambda: self.clear_history(self.recent_keys, self.recent_keys_menu, 1))
            self.recent_keys_menu.addSeparator()
        elif type == 2:
            clear_action = self.recent_private_keys_menu.addAction("Wyczyść historię ostatnich kluczy prywatnych")
            clear_action.triggered.connect(lambda: self.clear_history(self.recent_private_keys, self.recent_private_keys_menu, 2))
            self.recent_private_keys_menu.addSeparator()
        elif type == 3:
            clear_action = self.recent_public_keys_menu.addAction("Wyczyść historię ostatnich kluczy publicznych")
            clear_action.triggered.connect(lambda: self.clear_history(self.recent_public_keys, self.recent_public_keys_menu, 3))
            self.recent_public_keys_menu.addSeparator()

    def _update_recent_files_menu(self):
        self.recent_files_menu.clear()
        self._add_menu_actions(0)
        for file in self.recent_files:
            action = self.recent_files_menu.addAction(file)
            action.triggered.connect(lambda checked, p=file: self.select_recent_file(p))

    def _update_recent_keys_menu(self):
        self.recent_keys_menu.clear()
        self._add_menu_actions(1)
        for key in self.recent_keys:
            action = self.recent_keys_menu.addAction(key)
            action.triggered.connect(lambda checked, p=key: self.select_recent_key(p))

    def _update_recent_private_keys_menu(self):
        self.recent_private_keys_menu.clear()
        self._add_menu_actions(2)
        for key in self.recent_private_keys:
            action = self.recent_private_keys_menu.addAction(key)
            action.triggered.connect(lambda checked, p=key: self.select_recent_private_key(p))

    def _update_recent_public_keys_menu(self):
        self.recent_public_keys_menu.clear()
        self._add_menu_actions(3)
        for key in self.recent_public_keys:
            action = self.recent_public_keys_menu.addAction(key)
            action.triggered.connect(lambda checked, p=key: self.select_recent_public_key(p))

    def _add_to_history(self, path, history_list, max_items=10):
        if path in history_list:
            history_list.remove(path)
        history_list.insert(0, path)
        if len(history_list) > max_items:
            history_list.pop()

    def select_recent_file(self, file_path):
        if not os.path.exists(file_path):
            if file_path in self.recent_files:
                self.recent_files.remove(file_path)
                self._update_recent_files_menu()
                self.settings.setValue("recent_files", self.recent_files)
            QMessageBox.warning(self, "Błąd", f"Plik: {file_path} nie istnieje. Usunięto go z historii ostatnich plików.")
            return

        self.file_path = file_path
        self.label.setText(f"Plik: {file_path}")
        self.label.setToolTip("Ścieżka: " + self.file_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.file_path))
        self.clear_file_button.setEnabled(True)
        self._add_to_history(self.file_path, self.recent_files)
        self._update_recent_files_menu()
        self.settings.setValue("recent_files", self.recent_files)

    def select_recent_key(self, file_path):
        if not os.path.exists(file_path):
            if file_path in self.recent_keys:
                self.recent_keys.remove(file_path)
                self._update_recent_keys_menu()
                self.settings.setValue("recent_keys", self.recent_keys)
            QMessageBox.warning(self, "Błąd", f"Plik: {file_path} nie istnieje. Usunięto go z historii ostatnich kluczy.")
            return

        self.key_path = file_path
        self.key_label.setText(f"Klucz: {file_path}")
        self.key_label.setToolTip(self.key_path)
        self.key_label.setToolTip("Ścieżka: " + self.key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.key_path))
        self.clear_key_button.setEnabled(True)
        self._add_to_history(self.key_path, self.recent_keys)
        self._update_recent_keys_menu()
        self.settings.setValue("recent_keys", self.recent_keys)

    def select_recent_private_key(self, file_path):
        if not os.path.exists(file_path):
            if file_path in self.recent_private_keys:
                self.recent_private_keys.remove(file_path)
                self._update_recent_private_keys_menu()
                self.settings.setValue("recent_private_keys", self.recent_private_keys)
            QMessageBox.warning(self, "Błąd", f"Plik: {file_path} nie istnieje. Usunięto go z historii ostatnich kluczy prywatnych.")
            return

        self.private_key_path = file_path
        self.rsa_private_key_label.setText(f"Klucz prywatny: {file_path}")
        self.rsa_private_key_label.setToolTip("Ścieżka: " + self.private_key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.private_key_path))
        self.clear_private_key_button.setEnabled(True)
        self._add_to_history(self.private_key_path, self.recent_private_keys)
        self._update_recent_private_keys_menu()
        self.settings.setValue("recent_private_keys", self.recent_private_keys)

    def select_recent_public_key(self, file_path):
        if not os.path.exists(file_path):
            if file_path in self.recent_public_keys:
                self.recent_public_keys.remove(file_path)
                self._update_recent_public_keys_menu()
                self.settings.setValue("recent_public_keys", self.recent_public_keys)
            QMessageBox.warning(self, "Błąd", f"Plik: {file_path} nie istnieje. Usunięto go z historii ostatnich kluczy publicznych.")
            return

        self.public_key_path = file_path
        self.rsa_public_key_label.setText(f"Klucz publiczny: {file_path}")
        self.rsa_public_key_label.setToolTip("Ścieżka: " + self.public_key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.public_key_path))
        self.clear_public_key_button.setEnabled(True)
        self._add_to_history(self.public_key_path, self.recent_public_keys)
        self._update_recent_public_keys_menu()
        self.settings.setValue("recent_public_keys", self.recent_public_keys)

    def clear_file_path(self):
        self.file_path = "" 
        self.label.setText("Przeciągnij tutaj lub wybierz plik")
        self.label.setToolTip("")
        self.clear_file_button.setEnabled(False)

    def select_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik", "", "All Files (*)", options=options)
        if file_path:
            self.file_path = file_path
            self.label.file_path = file_path
            self._add_to_history(self.file_path, self.recent_files)
            self.label.setText(f"Plik: {self.file_path}")
            self.label.setToolTip("Ścieżka: " + self.file_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.file_path))
            self.clear_file_button.setEnabled(True)
            self._update_recent_files_menu()
            self.settings.setValue("recent_files", self.recent_files)
        else:
            if self.file_path:
                self.label.setText(f"Plik: {self.file_path}")
                self.label.setToolTip("Ścieżka: " + self.file_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.file_path))
            else:
                self.label.setText("Przeciągnij tutaj lub wybierz plik")
                self.label.setToolTip("")
                self.clear_file_button.setEnabled(False)

    def clear_key_path(self):
        self.key_path = ""
        self.key_label.setText("Przeciągnij tutaj lub wybierz klucz")
        self.key_label.setToolTip("")
        self.clear_key_button.setEnabled(False)

    def select_key_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz klucz", "", "Key Files (*.key);;All Files (*)", options=options)
        if file_path:
            self.key_path = file_path
            self.label.file_path = file_path
            self._add_to_history(self.key_path, self.recent_keys)
            self.key_label.setText(f"Klucz: {self.key_path}")
            self.key_label.setToolTip("Ścieżka: " + self.key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.key_path))
            self.clear_key_button.setEnabled(True)
            self._update_recent_keys_menu()
            self.settings.setValue("recent_keys", self.recent_keys)
        else:
            if self.key_path:
                self.key_label.setText(f"Klucz: {self.key_path}")
                self.key_label.setToolTip("Ścieżka: " + self.key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.key_path))
            else:
                self.key_label.setText("Przeciągnij tutaj lub wybierz klucz")
                self.key_label.setToolTip("")
                self.clear_key_button.setEnabled(False)

    def clear_private_key_path(self):
        self.private_key_path = ""
        self.rsa_private_key_label.setText("Przeciągnij tutaj lub wybierz klucz prywatny")
        self.rsa_private_key_label.setToolTip("")
        self.clear_private_key_button.setEnabled(False)

    def select_private_key_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz klucz prywatny", "", "Key Files (*.key);;All Files (*)", options=options)
        if file_path:
            self.private_key_path = file_path
            self.label.file_path = file_path
            self._add_to_history(self.private_key_path, self.recent_private_keys)
            self.rsa_private_key_label.setText(f"Klucz prywatny: {self.private_key_path}")
            self.rsa_private_key_label.setToolTip("Ścieżka: " + self.private_key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.private_key_path))
            self.clear_private_key_button.setEnabled(True)
            self._update_recent_private_keys_menu()
            self.settings.setValue("recent_private_keys", self.recent_private_keys)
        else:
            if self.private_key_path:
                self.rsa_private_key_label.setText(f"Klucz prywatny: {self.private_key_path}")
                self.rsa_private_key_label.setToolTip("Ścieżka: " + self.private_key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.private_key_path))
            else:
                self.rsa_private_key_label.setText("Przeciągnij tutaj lub wybierz klucz prywatny")
                self.rsa_private_key_label.setToolTip("")
                self.clear_private_key_button.setEnabled(False)

    def clear_public_key_path(self):
        self.public_key_path = ""
        self.rsa_public_key_label.setText("Przeciągnij tutaj lub wybierz klucz publiczny")
        self.rsa_public_key_label.setToolTip("")
        self.clear_public_key_button.setEnabled(False)

    def select_public_key_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz klucz publiczny", "", "Key Files (*.key);;All Files (*)", options=options)
        if file_path:
            self.public_key_path = file_path
            self.label.file_path = file_path
            self._add_to_history(self.public_key_path, self.recent_public_keys)
            self.rsa_public_key_label.setText(f"Klucz publiczny: {self.public_key_path}")
            self.rsa_public_key_label.setToolTip("Ścieżka: " + self.public_key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.public_key_path))
            self.clear_public_key_button.setEnabled(True)
            self._update_recent_public_keys_menu()
            self.settings.setValue("recent_public_keys", self.recent_public_keys)
        else:
            if self.public_key_path:
                self.rsa_public_key_label.setText(f"Klucz publiczny: {self.public_key_path}")
                self.rsa_public_key_label.setToolTip("Ścieżka: " + self.public_key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.public_key_path))
            else:
                self.rsa_public_key_label.setText("Przeciągnij tutaj lub wybierz klucz publiczny")
                self.rsa_public_key_label.setToolTip("")
                self.clear_public_key_button.setEnabled(False)

    def generate_key(self):
        algorithm = self.algorithm_box.currentText()
        options = QFileDialog.Options()
        default_save_name = "Klucz.key"
        key_path, _ = QFileDialog.getSaveFileName(self, "Zapisz klucz", default_save_name, "Key Files (*.key);;All Files (*)", options=options)
        
        if not key_path:
            return
        
        try:
            if algorithm == "AES":
                key_size = int(self.aes_key_size_box.currentText()) // 8
                key = get_random_bytes(key_size)
                atomic_write_bytes(key_path, key)
                msg = f"Klucz AES {key_size * 8}-bitowy został wygenerowany!"

            elif algorithm == "3DES":
                while True:
                    candidate = get_random_bytes(24)
                    key = DES3.adjust_key_parity(candidate)
                    try:
                        DES3.new(key, DES3.MODE_EAX)
                        break
                    except ValueError:
                        continue
                atomic_write_bytes(key_path, key)
                msg = "Klucz 3DES 192-bitowy został wygenerowany!"

            elif algorithm == "XChaCha20-Poly1305":
                key = get_random_bytes(32)
                atomic_write_bytes(key_path, key)
                msg = "Klucz XChaCha20-Poly1305 256-bitowy został wygenerowany!"

            elif algorithm == "Threefish-Skein-MAC":
                key_size = int(self.threefish_key_size_box.currentText()) // 8
                key = get_random_bytes(key_size)
                atomic_write_bytes(key_path, key)
                msg = f"Klucz Threefish-Skein-MAC {key_size * 8}-bitowy został wygenerowany!"

            else:
                QMessageBox.warning(self, "Błąd", "Wybierz poprawny algorytm.")
                return

            self.key_path = key_path
            self.key_label.setText(f"Klucz: {self.key_path}")
            self.key_label.setToolTip("Ścieżka: " + self.key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.key_path))
            self.clear_key_button.setEnabled(True)
            self._add_to_history(self.key_path, self.recent_keys)
            self._update_recent_keys_menu()

            QMessageBox.information(self, "Sukces", msg)
        
        except PermissionError:
            QMessageBox.critical(self, "Błąd", "Brak uprawnień do zapisu w tej lokalizacji.")

        except OSError as e:
            if getattr(e, "errno", None) in (errno.ENOSPC, errno.EDQUOT):
                QMessageBox.critical(self, "Błąd", "Brak miejsca na dysku (nie da się zapisać klucza).")
            else:
                QMessageBox.critical(self, "Błąd", f"Błąd wejścia/wyjścia podczas zapisu klucza: {e}")

        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie udało się wygenerować/zapisać klucza: {e}")

    def generate_private_key(self):
        options = QFileDialog.Options()
        default_save_name = "Klucz prywatny.key"
        key_path, _ = QFileDialog.getSaveFileName(self, "Zapisz klucz prywatny", default_save_name, "Key Files (*.key);;All Files (*)", options=options)
        
        if not key_path:
            return

        try:
            rsa_key_size = int(self.rsa_key_size_box.currentText())
            rsa_key = RSA.generate(rsa_key_size)
            private_key = rsa_key.export_key()

            atomic_write_bytes(key_path, private_key)

            self.private_key_path = key_path
            self.rsa_private_key_label.setText(f"Klucz prywatny: {self.private_key_path}")
            self.rsa_private_key_label.setToolTip("Ścieżka: " + self.private_key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.private_key_path))
            self.clear_private_key_button.setEnabled(True)
            self._add_to_history(self.private_key_path, self.recent_private_keys)
            self._update_recent_private_keys_menu()

            QMessageBox.information(self, "Sukces", f"Klucz prywatny RSA-PSS {rsa_key.size_in_bits()}-bitowy został wygenerowany!")

        except PermissionError:
            QMessageBox.critical(self, "Błąd", "Brak uprawnień do zapisu w tej lokalizacji.")

        except OSError as e:
            if getattr(e, "errno", None) in (errno.ENOSPC, errno.EDQUOT):
                QMessageBox.critical(self, "Błąd", "Brak miejsca na dysku (nie da się zapisać klucza).")
            else:
                QMessageBox.critical(self, "Błąd", f"Błąd wejścia/wyjścia podczas zapisu klucza: {e}")

        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie udało się wygenerować/zapisać klucza prywatnego: {e}")

    def generate_public_key(self):
        if not self.private_key_path:
            QMessageBox.warning(self, "Błąd", "Najpierw wybierz lub wygeneruj klucz prywatny!")
            return

        options = QFileDialog.Options()
        default_save_name = "Klucz publiczny.key"
        key_path, _ = QFileDialog.getSaveFileName(self, "Zapisz klucz publiczny", default_save_name, "Key Files (*.key);;All Files (*)", options=options)
        
        if not key_path:
            return
        
        try:
            with open(self.private_key_path, "rb") as f:
                rsa_key = RSA.import_key(f.read())
            public_key = rsa_key.publickey().export_key()

            if not rsa_key.has_private():
                raise ValueError("Błąd: Wybrany klucz nie jest kluczem prywatnym!")

            if rsa_key.size_in_bits() != int(self.rsa_key_size_box.currentText()):
                raise ValueError(f"Błąd: Nieprawidłowa długość klucza prywatnego! Wymagany klucz prywatny {int(self.rsa_key_size_box.currentText())}-bitowy, a podany klucz prywatny jest długości {rsa_key.size_in_bits()} bitów.")

            atomic_write_bytes(key_path, public_key)

            self.public_key_path = key_path
            self.rsa_public_key_label.setText(f"Klucz publiczny: {self.public_key_path}")
            self.rsa_public_key_label.setToolTip(self.public_key_path)
            self.rsa_public_key_label.setToolTip("Ścieżka: " + self.public_key_path + " - kliknij dwukrotnie, aby otworzyć lokalizację pliku\nRozmiar pliku: " + _safe_file_size_fmt(self.public_key_path))
            self.clear_public_key_button.setEnabled(True)
            self._add_to_history(self.public_key_path, self.recent_public_keys)
            self._update_recent_public_keys_menu()

            QMessageBox.information(self, "Sukces", f"Klucz publiczny RSA-PSS {rsa_key.size_in_bits()}-bitowy został wygenerowany!")

        except FileNotFoundError:
            QMessageBox.critical(self, "Błąd", "Nie znaleziono pliku klucza prywatnego.")

        except PermissionError:
            QMessageBox.critical(self, "Błąd", "Brak uprawnień do odczytu/zapisu w tej lokalizacji.")

        except ValueError as e:
            if not str(e).startswith("Błąd:"):
                QMessageBox.critical(self, "Błąd", f"Nieprawidłowy klucz prywatny: {e}")
            else:
                QMessageBox.critical(self, "Błąd", str(e))

        except OSError as e:
            if getattr(e, "errno", None) in (errno.ENOSPC, errno.EDQUOT):
                QMessageBox.critical(self, "Błąd", "Brak miejsca na dysku (nie da się zapisać klucza).")
            else:
                QMessageBox.critical(self, "Błąd", f"Błąd wejścia/wyjścia: {e}")

        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie udało się wygenerować/zapisać klucza publicznego: {e}")

    def _get_free_bytes_for_destination(self, dst_path: str):
        try:
            dst_dir = os.path.dirname(os.path.abspath(dst_path)) or "."
            return shutil.disk_usage(dst_dir).free
        except Exception:
            return None

    def _confirm_free_space_for_output(self, dst_path: str, approx_output_bytes: int) -> bool:
        free = self._get_free_bytes_for_destination(dst_path)
        if free is None:
            return True

        reserve = 64 * 1024 * 1024  # zapas 64 MB
        required = int(approx_output_bytes) + reserve

        if free >= required:
            return True

        dst_dir = os.path.dirname(os.path.abspath(dst_path)) or "."
        msg = (
            "Wybrana lokalizacja może nie mieć wystarczająco miejsca na dysku.\n\n"
            f"Lokalizacja: {dst_dir}\n"
            f"Wolne miejsce: {sizeof_fmt(free)}\n"
            f"Szac. wymagane miejsce: {sizeof_fmt(required)}\n\n"
            f"Kontynuować mimo to?"
        )
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Mało miejsca na dysku")
        box.setText(msg)
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        box.button(QMessageBox.Yes).setText("Tak")
        box.button(QMessageBox.No).setText("Nie")

        return box.exec_() == QMessageBox.Yes

    def encrypt_file(self):
        if not self.file_path or not os.path.exists(self.file_path):
            if self.file_path and self.file_path in self.recent_files:
                self.recent_files.remove(self.file_path)
                self._update_recent_files_menu()
                self.settings.setValue("recent_files", self.recent_files)
            if not self.file_path:
                QMessageBox.warning(self, "Błąd", "Wybierz plik!")
            else:
                QMessageBox.warning(self, "Błąd", f"Plik: {self.file_path} nie istnieje. Usunięto go z historii ostatnich plików.")
                self.clear_file_path()
            return
        
        algorithm = self.algorithm_box.currentText()

        if algorithm == "RSA-PSS":
            if not self.private_key_path or not os.path.exists(self.private_key_path):
                if self.private_key_path and self.private_key_path in self.recent_private_keys:
                    self.recent_private_keys.remove(self.private_key_path)
                    self._update_recent_private_keys_menu()
                    self.settings.setValue("recent_private_keys", self.recent_private_keys)
                if not self.private_key_path:
                    QMessageBox.warning(self, "Błąd", "Wybierz klucz prywatny!")
                else:
                    QMessageBox.warning(self, "Błąd", f"Klucz prywatny: {self.private_key_path} nie istnieje. Usunięto go z historii ostatnich kluczy prywatnych.")
                    self.clear_private_key_path()
                return

            if not self.public_key_path or not os.path.exists(self.public_key_path):
                if self.public_key_path and self.public_key_path in self.recent_public_keys:
                    self.recent_public_keys.remove(self.public_key_path)
                    self._update_recent_public_keys_menu()
                    self.settings.setValue("recent_public_keys", self.recent_public_keys)
                if not self.public_key_path:
                    QMessageBox.warning(self, "Błąd", "Wybierz klucz publiczny!")
                else:
                    QMessageBox.warning(self, "Błąd", f"Klucz publiczny: {self.public_key_path} nie istnieje. Usunięto go z historii ostatnich kluczy publicznych.")
                    self.clear_public_key_path()
                return

            if not os.path.exists(self.private_key_path):
                QMessageBox.warning(self, "Błąd", "Wybrany klucz prywatny nie istnieje.")
                return

            if not os.path.exists(self.public_key_path):
                QMessageBox.warning(self, "Błąd", "Wybrany klucz publiczny nie istnieje.")
                return

            key_path = self.private_key_path
            public_key_path = self.public_key_path
            mode = None
            key_size = int(self.rsa_key_size_box.currentText())
            padding = self.rsa_padding_box.currentText()

        else:
            if not self.key_path or not os.path.exists(self.key_path):
                if self.key_path and self.key_path in self.recent_keys:
                    self.recent_keys.remove(self.key_path)
                    self._update_recent_keys_menu()
                    self.settings.setValue("recent_keys", self.recent_keys)
                if not self.key_path:
                    QMessageBox.warning(self, "Błąd", "Wybierz klucz!")
                else:
                    QMessageBox.warning(self, "Błąd", f"Klucz: {self.key_path} nie istnieje. Usunięto go z historii ostatnich kluczy.")
                    self.clear_key_path()
                return

            key_path = self.key_path
            if algorithm == "AES":
                public_key_path = None
                mode = self.aes_mode_box.currentText()
                key_size = int(self.aes_key_size_box.currentText())
                padding = None
            elif algorithm == "3DES":
                public_key_path = None
                mode = self.des_mode_box.currentText()
                key_size = 0
                padding = None
            elif algorithm == "Threefish-Skein-MAC":
                public_key_path = None
                mode = None
                key_size = int(self.threefish_key_size_box.currentText())
                padding = None
            else:
                public_key_path = None
                mode = None
                key_size = 0
                padding = None

        MAX_AES_FILE_SIZE = 1024 * 1024 * 1024 * 64 # limit 64GB
        MAX_RSA_FILE_SIZE = 1024 * 1024 # limit 1MB
        MAX_3DES_EAX_FILE_SIZE = 1024 * 1024 * 10 # limit 10MB
        MAX_3DES_FILE_SIZE = 1024 * 1024 * 1024 * 32 # limit 32GB
        file_size = os.path.getsize(self.file_path)

        if algorithm == "RSA-PSS":
            if file_size > MAX_RSA_FILE_SIZE:
                QMessageBox.warning(self, "Błąd", f"RSA-PSS nie nadaje się do plików większych niż {MAX_RSA_FILE_SIZE // (1024*1024)} MB!")
                return
        else:
            if algorithm == "AES":
                if file_size > MAX_AES_FILE_SIZE:
                    QMessageBox.warning(self, "Błąd", f"AES nie nadaje się do plików większych niż {MAX_AES_FILE_SIZE // (1024*1024*1024)} GB!")
                    return
            elif algorithm == "3DES":
                if mode == "EAX (AEAD)":
                    if file_size > MAX_3DES_EAX_FILE_SIZE:
                        QMessageBox.warning(self, "Błąd", f"3DES w trybie EAX nie nadaje się do plików większych niż {MAX_3DES_EAX_FILE_SIZE // (1024*1024)} MB!")
                        return
                else:
                    if file_size > MAX_3DES_FILE_SIZE:
                        QMessageBox.warning(self, "Błąd", f"3DES nie nadaje się do plików większych niż {MAX_3DES_FILE_SIZE // (1024*1024*1024)} GB!")
                        return

        if os.path.splitext(os.path.basename(self.file_path))[1] == '.enc':
            QMessageBox.warning(self, "Błąd", "Plik już jest zaszyfrowany!")
            return

        options = QFileDialog.Options()
        base = os.path.splitext(os.path.basename(self.file_path))
        default_save_name = base[0] + " - zaszyfrowany" + base[1] + ".enc"
        self.save_path, _ = QFileDialog.getSaveFileName(self, "Zapisz zaszyfrowany plik", default_save_name, "Encrypted Files (*.enc);;All Files (*)", options=options)
        
        if not self.save_path:
            return

        if not self._confirm_free_space_for_output(self.save_path, file_size):
            return

        self.toggle_ui(False)
        self.cancel_button.setVisible(True)
        self.taskbar_progress.setVisible(True)
        self.taskbar_progress.setValue(0)
        self.thread = EncryptDecryptThread(self.file_path, key_path, public_key_path, algorithm, mode, padding, key_size, save_path=self.save_path)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.finished_signal.connect(self.operation_finished)
        self.thread.start()

    def decrypt_file(self):
        if not self.file_path or not os.path.exists(self.file_path):
            if self.file_path and self.file_path in self.recent_files:
                self.recent_files.remove(self.file_path)
                self._update_recent_files_menu()
                self.settings.setValue("recent_files", self.recent_files)
            if not self.file_path:
                QMessageBox.warning(self, "Błąd", "Wybierz plik!")
            else:
                QMessageBox.warning(self, "Błąd", f"Plik: {self.file_path} nie istnieje. Usunięto go z historii ostatnich plików.")
                self.clear_file_path()
            return

        algorithm = self.algorithm_box.currentText()

        if algorithm == "RSA-PSS":
            if not self.private_key_path or not os.path.exists(self.private_key_path):
                if self.private_key_path and self.private_key_path in self.recent_private_keys:
                    self.recent_private_keys.remove(self.private_key_path)
                    self._update_recent_private_keys_menu()
                    self.settings.setValue("recent_private_keys", self.recent_private_keys)
                if not self.private_key_path:
                    QMessageBox.warning(self, "Błąd", "Wybierz klucz prywatny!")
                else:
                    QMessageBox.warning(self, "Błąd", f"Klucz prywatny: {self.private_key_path} nie istnieje. Usunięto go z historii ostatnich kluczy prywatnych.")
                    self.clear_private_key_path()
                return
            
            if not self.public_key_path or not os.path.exists(self.public_key_path):
                if self.public_key_path and self.public_key_path in self.recent_public_keys:
                    self.recent_public_keys.remove(self.public_key_path)
                    self._update_recent_public_keys_menu()
                    self.settings.setValue("recent_public_keys", self.recent_public_keys)
                if not self.public_key_path:
                    QMessageBox.warning(self, "Błąd", "Wybierz klucz publiczny!")
                else:
                    QMessageBox.warning(self, "Błąd", f"Klucz publiczny: {self.public_key_path} nie istnieje. Usunięto go z historii ostatnich kluczy publicznych.")
                    self.clear_public_key_path()
                return

            key_path = self.private_key_path
            public_key_path = self.public_key_path
            mode = None
            key_size = int(self.rsa_key_size_box.currentText())
            padding = self.rsa_padding_box.currentText()
        else:
            if not self.key_path or not os.path.exists(self.key_path):
                if self.key_path and self.key_path in self.recent_keys:
                    self.recent_keys.remove(self.key_path)
                    self._update_recent_keys_menu()
                    self.settings.setValue("recent_keys", self.recent_keys)
                if not self.key_path:
                    QMessageBox.warning(self, "Błąd", "Wybierz klucz!")
                else:
                    QMessageBox.warning(self, "Błąd", f"Klucz: {self.key_path} nie istnieje. Usunięto go z historii ostatnich kluczy.")
                    self.clear_key_path()
                return

            key_path = self.key_path
            if algorithm == "AES":
                public_key_path = None
                mode = self.aes_mode_box.currentText()
                key_size = int(self.aes_key_size_box.currentText())
                padding = None
            elif algorithm == "3DES":
                public_key_path = None
                mode = self.des_mode_box.currentText()
                key_size = 0
                padding = None
            elif algorithm == "Threefish-Skein-MAC":
                public_key_path = None
                mode = None
                key_size = int(self.threefish_key_size_box.currentText())
                padding = None
            else:
                public_key_path = None
                mode = None
                key_size = 0
                padding = None

        if os.path.splitext(os.path.basename(self.file_path))[1] != '.enc':
            QMessageBox.warning(self, "Błąd", "Plik nie jest zaszyfrowany!")
            return

        options = QFileDialog.Options()
        base = os.path.splitext(os.path.basename(self.file_path))[0]
        base2 = os.path.splitext(base)
        if "- zaszyfrowany" in base:
            default_save_name = base.replace("- zaszyfrowany", "- deszyfrowany")
        else:
            default_save_name = base2[0] + ' - deszyfrowany' + base2[1]
        self.save_path, _ = QFileDialog.getSaveFileName(self, "Zapisz deszyfrowany plik", default_save_name, "All Files (*)", options=options)
        
        if not self.save_path:
            return
        
        if not self._confirm_free_space_for_output(self.save_path, os.path.getsize(self.file_path)):
            return

        self.toggle_ui(False)
        self.cancel_button.setVisible(True)
        QTimer.singleShot(0, self.adjustSize)
        self.taskbar_progress.setVisible(True)
        self.taskbar_progress.setValue(0)
        self.thread = EncryptDecryptThread(self.file_path, key_path, public_key_path, algorithm, mode, padding, key_size, decrypt=True, save_path=self.save_path)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.finished_signal.connect(self.operation_finished)
        self.thread.start()

    def update_progress(self, value, eta_seconds, avg_ram_mb):
        self.progress_bar.setValue(value)
        if value > 0:
            self.taskbar_progress.setVisible(True)
        self.taskbar_progress.setValue(value)

        if eta_seconds is None or eta_seconds < 0:
            eta_text = "szac. —"
        else:
            h = eta_seconds // 3600
            m = (eta_seconds % 3600) // 60
            s = eta_seconds % 60
            eta_text = f"ETA: {h:02d}:{m:02d}:{s:02d}"

        self.progress_bar.setFormat(f"{value}% — {eta_text}")

    def cancel_operation(self):
        if hasattr(self, "thread") and self.thread.isRunning():
            try:
                self.thread.request_stop()
            except Exception:
                pass
            self.cancel_button.setEnabled(False)
            QTimer.singleShot(3000, self._cancel_force_check)
            QTimer.singleShot(0, self.adjustSize)

    def _cancel_force_check(self):
        if hasattr(self, "thread") and self.thread.isRunning():
            try:
                self.thread.terminate()
                self.thread.wait()
            except Exception:
                pass

        self.cancel_button.setVisible(False)
        self.cancel_button.setEnabled(True)
        self.taskbar_progress.setVisible(False)
        self.toggle_ui(True)
        QTimer.singleShot(0, self.adjustSize)

    def operation_finished(self, message):
        if self.progress_bar.value != 0:
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("0%")
        self.cancel_button.setVisible(False)
        self.taskbar_progress.setVisible(False)
        self.toggle_ui(True)
        QTimer.singleShot(0, self.adjustSize)
        if "Błąd" in message:
            QMessageBox.critical(self, "Błąd", message.replace("Błąd: ", ""))
        elif "Info" in message:
            QMessageBox.information(self, "Informacja", message.replace("Info: ", ""))
        elif "Sukces" in message:
            QMessageBox.information(self, "Sukces", message.replace("Sukces: ", ""))
        else:
            QMessageBox.information(self, "Błąd", message)

        if "zaszyfrowany" in message:
            dialog = QMessageBox(self)
            dialog.setWindowTitle("Usuwanie pliku")
            dialog.setText("Czy chcesz usunąć oryginalny plik?")
            dialog.setIcon(QMessageBox.Question)
            tak_button = dialog.addButton("Tak", QMessageBox.YesRole)
            nie_button = dialog.addButton("Nie", QMessageBox.NoRole)
            secure_chk = QCheckBox("Usuń bezpiecznie (zalecane)")
            dialog.setCheckBox(secure_chk)
            dialog.exec_()

            if dialog.clickedButton() == tak_button:
                secure_delete = False
                try:
                    cb = dialog.checkBox()
                    if cb is not None:
                        secure_delete = cb.isChecked()
                except Exception:
                    secure_delete = False

                if secure_delete:
                    success, msg = _hybrid_crypto_erase(self.file_path)
                    if success:
                        QMessageBox.information(self, "Sukces", "Oryginalny plik został bezpiecznie usunięty.")
                        self.file_path = ""
                        self.label.setText("Wybierz plik")
                        self.label.setToolTip("")
                    else:
                        QMessageBox.warning(self, "Błąd", f"Nie udało się bezpiecznie usunąć pliku: {msg}")
                else:
                    try:
                        os.remove(self.file_path)
                        QMessageBox.information(self, "Sukces", "Oryginalny plik został usunięty.")
                        self.file_path = ""
                        self.label.setText("Wybierz plik")
                        self.label.setToolTip("")
                    except Exception as e:
                        QMessageBox.warning(self, "Błąd", f"Nie udało się usunąć pliku: {str(e)}")

        elif "deszyfrowany" in message:
            dialog = QMessageBox(self)
            dialog.setWindowTitle("Usuwanie pliku")
            dialog.setText("Czy chcesz usunąć zaszyfrowany plik?")
            dialog.setIcon(QMessageBox.Question)
            tak_button = dialog.addButton("Tak", QMessageBox.YesRole)
            nie_button = dialog.addButton("Nie", QMessageBox.NoRole)
            dialog.exec_()

            if dialog.clickedButton() == tak_button:
                try:
                    os.remove(self.file_path)
                    QMessageBox.information(self, "Sukces", "Zaszyfrowany plik został usunięty.")
                    self.file_path = ""
                    self.label.setText("Wybierz plik")
                    self.label.setToolTip("")
                except Exception as e:
                    QMessageBox.warning(self, "Błąd", f"Nie udało się usunąć pliku: {str(e)}")

    def _init_taskbar_progress(self):
        self.taskbar_button = QWinTaskbarButton(self)
        self.taskbar_button.setWindow(self.windowHandle())
        self.taskbar_progress = self.taskbar_button.progress()
        self.taskbar_progress.setVisible(False)

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self._init_taskbar_progress)

    def toggle_ui(self, enabled):
        for ctrl in self.all_controls:
            ctrl.setEnabled(enabled)
        if self.auto_theme_checkbox.isChecked():
            self.dark_theme_button.setEnabled(False)
            self.light_theme_button.setEnabled(False)

    def toggle_additional_options(self):
        if self.additional_options_widget.isVisible():
            self.additional_options_widget.setVisible(False)
            self.additional_options_button.setText("Ustawienia algorytmu ▼")
        else:
            self.additional_options_widget.setVisible(True)
            self.additional_options_button.setText("Ustawienia algorytmu ▲")

        QTimer.singleShot(0, self.adjustSize)

    def update_algorithm_settings(self):
        algorithm = self.algorithm_box.currentData()
        if algorithm is None:
            return

        for widgets_list in self.algorithm_widgets.values():
            for widget in widgets_list:
                widget.setVisible(False)

        for widget in self.algorithm_widgets.get(algorithm, []):
            widget.setVisible(True)

        if algorithm == "RSA-PSS":
            self.key_button.setVisible(False)
            self.generate_key_button.setVisible(False)
            self.key_label.setVisible(False)
            self.clear_key_button.setVisible(False)
            self.recent_keys_button.setVisible(False)
            self.key_group.setTitle("Klucze")
        else:
            self.key_button.setVisible(True)
            self.generate_key_button.setVisible(True)
            self.key_label.setText("Wybierz lub wygeneruj klucz:")
            self.key_group.setTitle("Klucz")
            self.key_label.setVisible(True)
            self.clear_key_button.setVisible(True)
            self.recent_keys_button.setVisible(True)
            self.clear_private_key_path()
            self.clear_public_key_path()
            self.clear_key_path()

        has_additional = bool(self.algorithm_widgets.get(algorithm))
        self.additional_options_button.setVisible(has_additional)
        self.additional_options_widget.setVisible(False)
        self.additional_options_button.setText("Ustawienia algorytmu ▼")

        QTimer.singleShot(0, self.adjustSize)

    def _read_windows_apps_light_theme(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return bool(value)
        except Exception:
            return True

    def _get_system_theme(self):
        try:
            light = self._read_windows_apps_light_theme()
            return "light" if light else "dark"
        except Exception:
            return "light"

    def _apply_system_theme(self):
        system_theme = self._get_system_theme()
        if system_theme == "light":
            self._apply_light_theme()
        else:
            self._apply_dark_theme()
        self.settings.setValue("theme_mode", system_theme)

    def on_system_theme_check(self):
        if not self.auto_theme_checkbox.isChecked():
            return
        current_system = self._get_system_theme()
        saved = self.settings.value("theme_mode", "dark")
        if current_system != saved:
            if current_system == "light":
                self._apply_light_theme()
            else:
                self._apply_dark_theme()
            self.settings.setValue("theme_mode", current_system)

    def on_auto_theme_changed(self, state):
        enabled = (state == Qt.Checked)
        self.settings.setValue("auto_theme", enabled)
        if enabled:
            self._apply_system_theme()
            self.system_theme_timer.start()
            self.light_theme_button.setEnabled(False)
            self.dark_theme_button.setEnabled(False)
        else:
            self.system_theme_timer.stop()
            self.light_theme_button.setEnabled(True)
            self.dark_theme_button.setEnabled(True)

    def _update_filelabel_styles(self):
        for name in ("label", "key_label", "rsa_private_key_label", "rsa_public_key_label"):
            widget = getattr(self, name, None)
            if widget is not None and hasattr(widget, "reset_style"):
                try:
                    widget.reset_style()
                except Exception:
                    pass

    def _apply_dark_theme(self):
        self.setStyleSheet(self.dark_stylesheet)
        self.settings.setValue("theme_mode", "dark")
        self._update_filelabel_styles()

    def _apply_light_theme(self):
        self.setStyleSheet(self.light_stylesheet)
        self.settings.setValue("theme_mode", "light")
        self._update_filelabel_styles()

    def set_theme_mode(self, mode: str):
        if mode == "light":
            self._apply_light_theme()
        else:
            self._apply_dark_theme()
        self.auto_theme_checkbox.setChecked(False)
        self.settings.setValue("auto_theme", False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    if getattr(sys, 'frozen', False):
        application_path = sys._MEIPASS
    elif __file__:
        application_path = os.path.dirname(__file__)
    icon_path = os.path.join(application_path, "assets", "icon.ico")
    app.setWindowIcon(QIcon(icon_path))
    window = FileEncryptor()
    window.setWindowIcon(QIcon(icon_path))
    window.show()
    app.exec_()