import base64
import hashlib
import os

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import DES3


SALT_SIZE = 16

PASSWORD_MIN_LENGTH = 12
PASSWORD_RECOMMENDED_LENGTH = 16
PASSWORD_MAX_LENGTH = 128

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024
ARGON2_PARALLELISM = 4

PBKDF2_ITERATIONS = 600_000

MAX_ARGON2_TIME_COST = 10
MAX_ARGON2_MEMORY_COST = 256 * 1024
MAX_ARGON2_PARALLELISM = 16
MAX_PBKDF2_ITERATIONS = 5_000_000


def create_kdf_params(kdf_name: str) -> dict:
    salt = base64.b64encode(
        os.urandom(SALT_SIZE)
    ).decode("ascii")

    if kdf_name == "argon2id":
        return {
            "name": "argon2id",
            "salt": salt,
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
        }

    if kdf_name == "pbkdf2-sha256":
        return {
            "name": "pbkdf2-sha256",
            "salt": salt,
            "iterations": PBKDF2_ITERATIONS,
        }

    raise ValueError(
        "Unsupported password key derivation function."
    )


def derive_password_key(
    password: str,
    key_length_bits: int,
    kdf_params: dict,
    algorithm_name: str,
) -> bytes:
    if not password:
        raise ValueError(
            "Password cannot be empty."
        )

    if not key_length_bits or key_length_bits % 8 != 0:
        raise ValueError(
            "Invalid derived key length."
        )

    salt = _decode_salt(
        kdf_params.get("salt")
    )

    key_length = key_length_bits // 8
    password_bytes = password.encode("utf-8")

    kdf_name = kdf_params.get("name")

    if kdf_name == "argon2id":
        key = _derive_argon2id(
            password_bytes,
            salt,
            key_length,
            kdf_params,
        )

    elif kdf_name == "pbkdf2-sha256":
        key = _derive_pbkdf2(
            password_bytes,
            salt,
            key_length,
            kdf_params,
        )

    else:
        raise ValueError(
            "Unsupported password key derivation function."
        )

    if algorithm_name == "3DES":
        key = DES3.adjust_key_parity(key)

    return key


def _derive_argon2id(
    password: bytes,
    salt: bytes,
    key_length: int,
    params: dict,
) -> bytes:
    time_cost = int(
        params.get("time_cost", 0)
    )
    memory_cost = int(
        params.get("memory_cost", 0)
    )
    parallelism = int(
        params.get("parallelism", 0)
    )

    if not 1 <= time_cost <= MAX_ARGON2_TIME_COST:
        raise ValueError(
            "Invalid Argon2id time cost."
        )

    if not 8 * 1024 <= memory_cost <= MAX_ARGON2_MEMORY_COST:
        raise ValueError(
            "Invalid Argon2id memory cost."
        )

    if not 1 <= parallelism <= MAX_ARGON2_PARALLELISM:
        raise ValueError(
            "Invalid Argon2id parallelism."
        )

    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_length,
        type=Type.ID,
    )


def _derive_pbkdf2(
    password: bytes,
    salt: bytes,
    key_length: int,
    params: dict,
) -> bytes:
    iterations = int(
        params.get("iterations", 0)
    )

    if not 100_000 <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise ValueError(
            "Invalid PBKDF2 iteration count."
        )

    return hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        iterations,
        dklen=key_length,
    )


def _decode_salt(value: str | None) -> bytes:
    if not value:
        raise ValueError(
            "KDF salt is missing."
        )

    try:
        salt = base64.b64decode(
            value,
            validate=True,
        )
    except ValueError as exc:
        raise ValueError(
            "Invalid KDF salt."
        ) from exc

    if not 16 <= len(salt) <= 64:
        raise ValueError(
            "Invalid KDF salt length."
        )

    return salt