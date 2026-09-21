import json
import struct


MAGIC = b"XYCR"
VERSION = 1
MAX_HEADER_SIZE = 64 * 1024


def encode_header(header: dict) -> bytes:
    data = json.dumps(
        header,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")

    return (
        MAGIC
        + struct.pack(">B", VERSION)
        + struct.pack(">I", len(data))
        + data
    )


def write_header(fout, header: dict) -> bytes:
    header_bytes = encode_header(header)
    fout.write(header_bytes)

    return header_bytes


def read_header(fin, lang=None) -> tuple[dict, bytes]:
    magic = fin.read(4)

    if magic != MAGIC:
        raise ValueError(_error_message(lang))

    version_data = fin.read(1)

    if len(version_data) != 1:
        raise ValueError(_error_message(lang))

    version = struct.unpack(">B", version_data)[0]

    if version != VERSION:
        raise ValueError(_error_message(lang))

    length_data = fin.read(4)

    if len(length_data) != 4:
        raise ValueError(_error_message(lang))

    length = struct.unpack(">I", length_data)[0]

    if length <= 0 or length > MAX_HEADER_SIZE:
        raise ValueError(_error_message(lang))

    data = fin.read(length)

    if len(data) != length:
        raise ValueError(_error_message(lang))

    try:
        metadata = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(_error_message(lang)) from exc

    if not isinstance(metadata, dict):
        raise ValueError(_error_message(lang))

    if not isinstance(metadata.get("algorithm"), str):
        raise ValueError(_error_message(lang))

    if not isinstance(metadata.get("params"), dict):
        raise ValueError(_error_message(lang))

    header_bytes = magic + version_data + length_data + data

    return metadata, header_bytes


def _error_message(lang):
    if lang:
        return lang.t("operations.error.8")

    return "Incorrect header format."