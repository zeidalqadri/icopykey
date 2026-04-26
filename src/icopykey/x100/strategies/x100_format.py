"""
Format strategy for the X100/CopyKey proprietary export format.

The CopyKey Manager and similar devices often embed card dumps in a
custom binary container with a fixed magic string and version fields.
This strategy attempts to parse such files by interpreting a small
header at the beginning of the file and extracting the raw card
payload.  The structure is intentionally simple to allow future
adaptation when the exact format is reverse engineered.

The default header layout is::

    struct Header {
        char magic[4];        // constant "X100"
        uint8_t version_major;
        uint8_t version_minor;
        uint16_t header_len;  // size of header including this struct
        uint32_t payload_len; // number of bytes of card data
    };

Following the header are ``header_len - sizeof(Header)`` bytes of
reserved or metadata fields which are currently ignored.  The card
payload begins immediately afterwards and continues for
``payload_len`` bytes.  If ``payload_len`` is zero or otherwise
inconsistent with the file size the strategy will fall back to using
all remaining bytes as the payload when ``strict=False``.

This implementation does not perform any obfuscation/verification of
the payload; it simply validates that the payload length is a multiple
of 16 and pads it if necessary when ``strict=False``.
"""

from __future__ import annotations

import struct
from typing import Optional, Tuple, List

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..engine import MifareClassicDump
from .base import FormatStrategy, StrategyRegistry


class X100FormatStrategy(FormatStrategy):
    """Strategy for CopyKey/X100 dumps."""

    name = "x100"
    # Default header struct: magic (4s), version_major (B), version_minor (B), header_len (H), payload_len (I)
    _HEADER_STRUCT = struct.Struct(">4sBBHI")
    _MAGIC = b"X100"

    def __init__(self, header_magic: Optional[bytes] = None, header_struct: Optional[struct.Struct] = None) -> None:
        self.magic = header_magic or self._MAGIC
        self.header_struct = header_struct or self._HEADER_STRUCT

    def can_handle(self, data: bytes) -> bool:
        # A valid X100 dump begins with the magic string
        return len(data) >= self.header_struct.size and data.startswith(self.magic)

    def normalize(self, data: bytes, strict: bool = True) -> 'MifareClassicDump':
        if not self.can_handle(data):
            raise ValueError("Data does not appear to be an X100 dump")
        header_size = self.header_struct.size
        if len(data) < header_size:
            raise ValueError("File too short for X100 header")
        magic, ver_major, ver_minor, header_len, payload_len = self.header_struct.unpack_from(data, 0)
        # Basic sanity checks
        if magic != self.magic:
            raise ValueError(f"Unexpected magic {magic!r}")
        if header_len < header_size:
            if strict:
                raise ValueError(f"Header length {header_len} too small")
            header_len = header_size
        # Determine where payload begins
        payload_offset = header_len
        # Validate payload length
        available = len(data) - payload_offset
        if payload_len == 0 or payload_len > available:
            if strict:
                raise ValueError(
                    f"Payload length {payload_len} invalid; only {available} bytes remain after header"
                )
            # Use whatever remains
            payload_len = available
        payload = data[payload_offset:payload_offset + payload_len]
        # Ensure payload is block aligned
        if len(payload) % 16 != 0:
            if strict:
                raise ValueError("Payload length is not a multiple of 16 bytes")
            # Pad with zeros to nearest block
            missing = 16 - (len(payload) % 16)
            payload += b"\x00" * missing
        # Extract UID if present in header metadata (unknown).  For now
        # just set UID to None; the RawFormatStrategy will derive the UID
        # from block 0, but X100 dumps might embed it in the header.
        uid: Optional[str] = None
        # Extract keys from the payload
        keys = self._extract_keys(payload)
        return MifareClassicDump(uid=uid, data=payload, keys=keys, size=len(payload))

    def _extract_keys(self, data: bytes) -> List[Tuple[Optional[str], Optional[str]]]:
        """Delegate to RawFormatStrategy key extraction.

        Rather than reimplement the logic here we import the raw
        strategy's extraction method.  This avoids duplication and
        ensures consistent key parsing across formats.
        """
        from .raw_format import RawFormatStrategy  # local import to avoid cycle
        raw = RawFormatStrategy()
        return raw._extract_keys(data)  # type: ignore[attr-defined]


# Register strategy on import
StrategyRegistry.register(X100FormatStrategy())