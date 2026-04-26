"""
Input validators for CopyKEY CLI.

All validators return the validated/sanitized value on success
and raise a typed :class:`ValidationError` on failure.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .errors import (
    InvalidAccessBitsError,
    InvalidCardTypeError,
    InvalidHexError,
    InvalidKeyError,
    InvalidUIDError,
    FileOperationError,
)

# Recognised card types with their sector counts and descriptions
CARD_TYPES: dict[str, dict[str, Any]] = {
    "mifare_classic_1k": {"sectors": 16, "description": "MIFARE Classic 1K (S50)", "uid_bytes": 4},
    "mifare_classic_4k": {"sectors": 40, "description": "MIFARE Classic 4K (S70)", "uid_bytes": 4},
    "id_card": {"sectors": 0, "description": "ID/PID/NSC Card", "uid_bytes": (4, 5)},
    "ntag_ultralight": {"sectors": 0, "description": "NTAG/Ultralight EV1", "uid_bytes": 7},
}

# Valid access bit masks
VALID_ACCESS_BITS = {
    "FF078069": "Transport configuration (default)",
    "78778800": "Read-only (keys not readable)",
    "FF0780BC": "Transport + inverted",
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HEX_STRIP_RE = re.compile(r"[\s:.-]+")


def validate_hex(value: str, field_name: str = "value") -> str:
    """Validate and normalise a hex string.

    Strips whitespace / colons / dashes, upper-cases, and checks
    that only hex characters remain.

    Returns
    -------
    str
        Uppercase hex string with delimiters removed.

    Raises
    ------
    InvalidHexError
        If the value contains non-hex characters after stripping.
    """
    cleaned = _HEX_STRIP_RE.sub("", value)
    if not cleaned:
        raise InvalidHexError(value, field_name)
    if not _HEX_RE.match(cleaned):
        raise InvalidHexError(value, field_name)
    return cleaned.upper()


def validate_key(value: str, expected_bytes: int = 6) -> bytes:
    """Validate a MIFARE / crypto key.

    Parameters
    ----------
    value : str
        Hex string (12 chars for 6-byte MIFARE key).
    expected_bytes : int
        Expected key length in bytes (default 6 for MIFARE).

    Returns
    -------
    bytes
        The decoded key.

    Raises
    ------
    InvalidKeyError
        If the key is not the right length or contains non-hex chars.
    """
    try:
        cleaned = validate_hex(value, "key")
    except InvalidHexError:
        raise InvalidKeyError(value, expected_bytes)

    if len(cleaned) != expected_bytes * 2:
        raise InvalidKeyError(value, expected_bytes)
    return bytes.fromhex(cleaned)


def validate_uid(value: str) -> bytes:
    """Validate a card UID.

    Accepts 4, 7, or 10 byte UIDs (8, 14, 20 hex digits).
    Supports colon/space/dash delimiters.

    Returns
    -------
    bytes
        The decoded UID.

    Raises
    ------
    InvalidUIDError
        If the UID is not a valid length.
    """
    try:
        cleaned = validate_hex(value, "UID")
    except InvalidHexError:
        raise InvalidUIDError(value)

    valid_lengths = {8, 14, 20}
    if len(cleaned) not in valid_lengths:
        raise InvalidUIDError(value)
    return bytes.fromhex(cleaned)


def validate_access_bits(value: str) -> bytes:
    """Validate MIFARE Classic access bits.

    Returns
    -------
    bytes
        4-byte access bits.

    Raises
    ------
    InvalidAccessBitsError
        If not valid 4-byte hex.
    """
    try:
        cleaned = validate_hex(value, "access bits")
    except InvalidHexError:
        raise InvalidAccessBitsError(value)

    if len(cleaned) != 8:
        raise InvalidAccessBitsError(value)
    return bytes.fromhex(cleaned)


def validate_card_type(value: str) -> str:
    """Validate and normalise a card type string.

    Accepts common aliases (e.g. "1k", "s50", "mifare 1k")
    and normalises to the canonical key.

    Returns
    -------
    str
        Canonical card-type key (see ``CARD_TYPES``).

    Raises
    ------
    InvalidCardTypeError
        If the value does not match any known type.
    """
    v = value.lower().replace(" ", "_").replace("-", "_")

    aliases: dict[str, str] = {
        "mifare_classic_1k": "mifare_classic_1k",
        "mifare_classic_4k": "mifare_classic_4k",
        "id_card": "id_card",
        "ntag_ultralight": "ntag_ultralight",
        "1k": "mifare_classic_1k",
        "s50": "mifare_classic_1k",
        "mifare_1k": "mifare_classic_1k",
        "mifare1k": "mifare_classic_1k",
        "4k": "mifare_classic_4k",
        "s70": "mifare_classic_4k",
        "mifare_4k": "mifare_classic_4k",
        "mifare4k": "mifare_classic_4k",
        "id": "id_card",
        "pid": "id_card",
        "nsc": "id_card",
        "id_pid_nsc": "id_card",
        "ntag": "ntag_ultralight",
        "ultralight": "ntag_ultralight",
        "ntag_ev1": "ntag_ultralight",
        "ntag_ultralight_ev1": "ntag_ultralight",
    }

    mapped = aliases.get(v)
    if mapped is None:
        raise InvalidCardTypeError(value)
    return mapped


def validate_vid_pid(value: str, field_name: str = "VID/PID") -> int:
    """Validate a VID or PID hex value (16-bit, 4 hex chars).

    Returns
    -------
    int
        The integer value.

    Raises
    ------
    InvalidHexError
        If invalid.
    """
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    try:
        cleaned = validate_hex(cleaned, field_name)
    except InvalidHexError:
        raise InvalidHexError(value, field_name)

    if len(cleaned) > 4:
        raise InvalidHexError(value, field_name)
    return int(cleaned, 16)


def validate_path(value: str, must_exist: bool = True, readable: bool = True) -> Path:
    """Validate a file path.

    Parameters
    ----------
    value : str
        Path string.
    must_exist : bool
        If True, the path must exist.
    readable : bool
        If True, the path must be readable.

    Returns
    -------
    Path
        Resolved absolute path.

    Raises
    ------
    FileOperationError
        If validation fails.
    """
    try:
        path = Path(value).expanduser().resolve()
    except (OSError, RuntimeError) as e:
        raise FileOperationError(value, "access", str(e))

    if must_exist and not path.exists():
        raise FileOperationError(value, "find", "file does not exist")

    if readable and must_exist and not os.access(str(path), os.R_OK):
        raise FileOperationError(value, "read", "permission denied")

    return path


def validate_filename(value: str) -> str:
    """Sanitize a user-provided filename.

    Strips path separators, null bytes, and dangerous characters.
    """
    cleaned = value.replace("\x00", "")
    cleaned = cleaned.replace("/", "_").replace("\\", "_")
    cleaned = cleaned.replace("..", "_")
    cleaned = cleaned.strip()
    if not cleaned:
        cleaned = "untitled"
    return cleaned[:255]


def validate_choice(value: str, valid_choices: list[str], default: str | None = None) -> str:
    """Validate a menu choice against allowed values.

    Returns the choice if valid, default if value is empty, or raises ValueError.
    """
    if not value.strip() and default is not None:
        return default
    if value in valid_choices:
        return value
    raise ValueError(f"Invalid choice '{value}'. Valid options: {', '.join(valid_choices)}")


def validate_integer(value: str, min_val: int = 0, max_val: int | None = None) -> int:
    """Validate an integer within range."""
    try:
        num = int(value.strip())
    except ValueError:
        raise ValueError(f"Not a valid integer: '{value}'")
    if num < min_val:
        raise ValueError(f"Value {num} is below minimum {min_val}")
    if max_val is not None and num > max_val:
        raise ValueError(f"Value {num} exceeds maximum {max_val}")
    return num


def validate_index(value: str, max_index: int) -> int:
    """Validate a list index within bounds."""
    return validate_integer(value, min_val=0, max_val=max_index)


def validate_sector_numbers(value: str, max_sectors: int) -> list[int]:
    """Parse a sector range expression like '0-15' or '0,1,5-10'.

    Returns
    -------
    list[int]
        Sorted, deduplicated list of sector indices.
    """
    parts = [p.strip() for p in value.split(",")]
    sectors: set[int] = set()

    for part in parts:
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                start = int(start_s.strip())
                end = int(end_s.strip())
            except ValueError:
                raise ValueError(f"Invalid range: '{part}'")
            if start < 0 or end >= max_sectors:
                raise ValueError(f"Range {start}-{end} out of bounds (0-{max_sectors - 1})")
            sectors.update(range(start, end + 1))
        else:
            try:
                n = int(part)
            except ValueError:
                raise ValueError(f"Invalid sector number: '{part}'")
            if n < 0 or n >= max_sectors:
                raise ValueError(f"Sector {n} out of bounds (0-{max_sectors - 1})")
            sectors.add(n)

    if not sectors:
        raise ValueError("No valid sectors specified")
    return sorted(sectors)
