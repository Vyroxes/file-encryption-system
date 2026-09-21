import secrets
import string
import sys

from functools import lru_cache
from pathlib import Path

from password_kdf import PASSWORD_MAX_LENGTH


SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?"
PASSPHRASE_SYMBOLS = "-_.!@#$%&+"

MIN_PASSPHRASE_WORDS = 4
DEFAULT_PASSPHRASE_WORDS = 6
MAX_PASSPHRASE_WORDS = 10


class PassphraseWordListError(ValueError):
    pass

def generate_random_password(
    length: int,
    uppercase: bool,
    numbers: bool,
    symbols: bool,
) -> str:
    groups = [
        string.ascii_lowercase,
    ]

    if uppercase:
        groups.append(
            string.ascii_uppercase
        )

    if numbers:
        groups.append(
            string.digits
        )

    if symbols:
        groups.append(
            SYMBOLS
        )

    if length < len(groups):
        raise ValueError(
            "Password length is too short."
        )

    result = [
        secrets.choice(group)
        for group in groups
    ]

    alphabet = "".join(groups)

    result.extend(
        secrets.choice(alphabet)
        for _ in range(
            length - len(result)
        )
    )

    secrets.SystemRandom().shuffle(
        result
    )

    return "".join(result)

def generate_passphrase(
    word_count: int,
    uppercase: bool,
    numbers: bool,
    symbols: bool,
) -> str:
    words = _load_wordlist()

    selected = [
        secrets.choice(words)
        for _ in range(word_count)
    ]

    if uppercase:
        selected = [
            word.capitalize()
            for word in selected
        ]

    separator = " "

    if symbols:
        separator = secrets.choice(
            PASSPHRASE_SYMBOLS
        )

    result = separator.join(
        selected
    )

    if numbers:
        result += str(
            secrets.randbelow(100)
        ).zfill(2)

    if len(result) > PASSWORD_MAX_LENGTH:
        raise ValueError(
            "Generated passphrase is too long."
        )

    return result

@lru_cache(maxsize=1)
def _load_wordlist() -> tuple[str, ...]:
    path = _wordlist_path()

    if not path.is_file():
        raise PassphraseWordListError(
            f"Passphrase word list not found:\n{path}"
        )

    words = []

    try:
        lines = path.read_text(
            encoding="utf-8-sig"
        ).splitlines()
    except OSError as exc:
        raise PassphraseWordListError(
            f"Could not read passphrase word list:\n{path}"
        ) from exc

    for line in lines:
        line = line.strip()

        if not line:
            continue

        parts = line.split(
            maxsplit=1
        )

        if len(parts) != 2:
            continue

        dice_code, word = parts

        if (
            len(dice_code) == 5
            and all(
                char in "123456"
                for char in dice_code
            )
        ):
            words.append(
                word.strip()
            )

    if len(words) != 7776:
        raise PassphraseWordListError(
            f"Invalid EFF word list.\n"
            f"Expected 7776 words, found {len(words)}.\n\n"
            f"File:\n{path}"
        )

    if len(set(words)) != 7776:
        raise PassphraseWordListError(
            "EFF word list contains duplicate words."
        )

    return tuple(words)

def _wordlist_path() -> Path:
    if hasattr(sys, "_MEIPASS"):
        base_path = Path(
            sys._MEIPASS
        )
    else:
        base_path = Path(
            __file__
        ).resolve().parent

    return (
        base_path/"resources"/"eff_large_wordlist.txt"
    )