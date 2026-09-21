import os
import tempfile

from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes

from algorithms import ALGORITHMS
from algorithms.pqc import ML_DSA_MODULES, ML_KEM_MODULES, SLH_DSA_MODULES


PQC_MODULES = {
    "ML-KEM": ML_KEM_MODULES,
    "ML-DSA": ML_DSA_MODULES,
    "SLH-DSA": SLH_DSA_MODULES,
}


def generate_key(
    key_type: str,
    public: bool,
    private_key_path: str,
    algorithm_name: str,
    key_length_bits: int | None,
    output_path: str,
    mode: str | None = None,
    lang=None,
    curve: str | None = None,
) -> str:
    algorithm = ALGORITHMS.get(algorithm_name)

    if not algorithm or algorithm["type"] != key_type:
        raise ValueError(
            _message(
                lang,
                "operations.error.9",
                "Algorithm not supported.",
            )
        )

    if algorithm_name in ("EdDSA", "ECDSA"):
        curves = algorithm.get(
            "curves",
            [],
        )

        if not curve or curve not in curves:
            error_key = (
                "operations.error.19"
                if algorithm_name == "EdDSA"
                else "operations.error.21"
            )

            fallback = (
                "EdDSA curve not supported."
                if algorithm_name == "EdDSA"
                else "ECDSA curve not supported."
            )

            raise ValueError(
                _message(
                    lang,
                    error_key,
                    fallback,
                )
            )

        key = _generate_ecc_key(
            public,
            private_key_path,
            curve,
            algorithm_name,
            lang,
        )

    else:
        key_lengths = algorithm.get(
            "mode_key_lengths",
            {},
        ).get(
            mode,
            algorithm.get("key_lengths", []),
        )

        if not key_lengths:
            message = _message(
                lang,
                "key.error.11",
                "Key generation for $ requires algorithm-specific parameters.",
            )

            raise ValueError(
                message.replace(
                    "$",
                    algorithm_name,
                )
            )

        if key_length_bits not in key_lengths:
            expected = ", ".join(
                str(length)
                for length in key_lengths
            )

            message = _message(
                lang,
                "key.error.6",
                "Invalid key length for the $ algorithm. Expected: #. Selected: @.",
            )

            raise ValueError(
                message
                .replace("$", algorithm_name)
                .replace("#", f"{expected} bits")
                .replace(
                    "@",
                    f"{key_length_bits} bits",
                )
            )

        if algorithm_name == "3DES":
            key = _generate_des3_key()

        elif algorithm_name in (
            "RSA-PSS",
            "RSA-OAEP",
        ):
            key = _generate_rsa_key(
                public,
                private_key_path,
                key_length_bits,
                algorithm_name,
                lang,
            )

        else:
            key = get_random_bytes(
                key_length_bits // 8
            )

    _atomic_write_bytes(
        output_path,
        key,
    )

    return output_path


def _generate_des3_key() -> bytes:
    while True:
        candidate = get_random_bytes(24)

        try:
            key = DES3.adjust_key_parity(candidate)
            DES3.new(key, DES3.MODE_EAX)
            return key
        except ValueError:
            continue


def _generate_rsa_key(
    public: bool,
    private_key_path: str,
    key_length_bits: int,
    algorithm_name: str,
    lang=None,
) -> bytes:
    if public:
        if not private_key_path or not os.path.exists(private_key_path):
            raise FileNotFoundError(_message(lang, "key.error.12", "Private key file not found."))

        try:
            with open(private_key_path, "rb") as file:
                private_key = RSA.import_key(file.read())
        except (ValueError, IndexError, TypeError) as exc:
            raise ValueError(_message(lang, "key.error.4", "This is not a valid private key.")) from exc

        if not private_key.has_private():
            raise ValueError(_message(lang, "key.error.4", "This is not a valid private key."))

        actual_key_length = private_key.size_in_bits()

        if actual_key_length != key_length_bits:
            message = _message(lang, "key.error.6", "Invalid key length for the $ algorithm. Expected: #. Selected: @.")
            raise ValueError(message.replace("$", algorithm_name).replace("#", f"{key_length_bits} bits").replace("@", f"{actual_key_length} bits"))

        return private_key.public_key().export_key(format="PEM")

    private_key = RSA.generate(
        key_length_bits,
        e=65537,
    )

    return private_key.export_key(
        format="PEM",
        pkcs=8,
    )

def _generate_ecc_key(
    public: bool,
    private_key_path: str,
    curve: str,
    algorithm_name: str,
    lang=None,
) -> bytes:
    crypto_curve = _get_ecc_curve(
        algorithm_name,
        curve,
    )

    if public:
        if (
            not private_key_path
            or not os.path.exists(
                private_key_path
            )
        ):
            raise FileNotFoundError(
                _message(
                    lang,
                    "key.error.12",
                    "Private key file not found.",
                )
            )

        try:
            with open(
                private_key_path,
                "rb",
            ) as file:
                private_key = (
                    ECC.import_key(
                        file.read()
                    )
                )

        except (
            ValueError,
            IndexError,
            TypeError,
        ) as exc:
            raise ValueError(
                _message(
                    lang,
                    "key.error.4",
                    "This is not a valid private key.",
                )
            ) from exc

        if not private_key.has_private():
            raise ValueError(
                _message(
                    lang,
                    "key.error.4",
                    "This is not a valid private key.",
                )
            )

        if (
            private_key.curve
            != crypto_curve
        ):
            message = _message(
                lang,
                "key.error.13",
                "Selected curve does not match the key. Key: $. Selected: #.",
            )

            raise ValueError(
                message
                .replace(
                    "$",
                    private_key.curve,
                )
                .replace(
                    "#",
                    crypto_curve,
                )
            )

        return (
            private_key
            .public_key()
            .export_key(
                format="PEM"
            )
            .encode("ascii")
        )

    private_key = ECC.generate(
        curve=crypto_curve,
    )

    return (
        private_key
        .export_key(
            format="PEM",
            use_pkcs8=True,
        )
        .encode("ascii")
    )

def _get_ecc_curve(
    algorithm_name: str,
    curve: str,
) -> str:
    if algorithm_name == "EdDSA":
        return curve

    ecdsa_curves = {
        "P-256 (secp256r1)": "P-256",
        "P-384 (secp384r1)": "P-384",
        "P-521 (secp521r1)": "P-521",
    }

    return ecdsa_curves[curve]

def generate_pqc_key_pair(
    algorithm_name: str,
    parameter_set: str,
    private_output_path: str,
    public_output_path: str,
) -> tuple[str, str]:
    try:
        module = PQC_MODULES[
            algorithm_name
        ][parameter_set]
    except KeyError as exc:
        raise ValueError(
            "PQC parameter set not supported."
        ) from exc

    public_key, private_key = (
        module.keygen()
    )

    _atomic_write_bytes(
        private_output_path,
        private_key,
    )

    _atomic_write_bytes(
        public_output_path,
        public_key,
    )

    return (
        private_output_path,
        public_output_path,
    )

def _atomic_write_bytes(output_path: str, data: bytes) -> None:
    directory = os.path.dirname(os.path.abspath(output_path)) or "."

    fd, temp_path = tempfile.mkstemp(
        prefix=".key_",
        suffix=".tmp",
        dir=directory,
    )

    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, output_path)

    except Exception:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        finally:
            raise

def _message(lang, key: str, fallback: str) -> str:
    if lang:
        return lang.t(key)

    return fallback