"""
Format strategy for raw MIFARE dumps (.mfd or .bin).

This strategy accepts any byte sequence whose length is a multiple of
16 and does not match the magic string used by proprietary formats
handled by other strategies.  It performs minimal validation and
returns a :class:`~x100_decrypt.engine.MifareClassicDump` with the UID
extracted from block 0 of sector 0 when available.
"""

from __future__ import annotations

from typing import Optional, Tuple, List

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..engine import MifareClassicDump
from .base import FormatStrategy, StrategyRegistry


class RawFormatStrategy(FormatStrategy):
    """Basic strategy for raw dumps with no header."""

    name = "raw"

    def can_handle(self, data: bytes) -> bool:
        # Accept any file that is a multiple of 16 bytes and at least
        # one block long.  Other strategies (e.g. X100) should check
        # their magic bytes before this one; the registry order ensures
        # that more specific strategies are considered first.
        return len(data) >= 16 and (len(data) % 16 == 0)

    def normalize(self, data: bytes, strict: bool = True) -> 'MifareClassicDump':
        # If strict, ensure size matches known card sizes (1K or 4K or
        # larger multiples of 16); otherwise we will pad or truncate to
        # the nearest 16‑byte boundary.
        payload = data
        if not payload:
            raise ValueError("Empty dump")
        if len(payload) % 16 != 0:
            if strict:
                raise ValueError(f"Payload length {len(payload)} is not multiple of 16")
            # pad with zeros to next 16
            missing = 16 - (len(payload) % 16)
            payload += b"\x00" * missing
        # Derive UID from manufacturer block (first 4 bytes) if present
        uid: Optional[str] = None
        if len(payload) >= 4:
            uid_bytes = payload[0:4]
            uid = uid_bytes.hex()
        # Extract keys from trailer blocks
        keys = self._extract_keys(payload)
        return MifareClassicDump(uid=uid, data=payload, keys=keys, size=len(payload))

    def _extract_keys(self, data: bytes) -> List[Tuple[Optional[str], Optional[str]]]:
        """Parse each sector's trailer block and return the keys.

        For 1K cards there are 16 sectors with 4 blocks each; for 4K
        cards there are 40 sectors with the first 32 sectors containing
        4 blocks and the remaining 8 containing 16 blocks.  Keys are
        stored in the trailer block (the last block of each sector).  Key
        A occupies bytes 0..5, access bits bytes 6..9 and key B bytes
        10..15.  When a key is all 0xFF or 0x00 it may be unknown;
        consumers should handle those cases.
        """
        keys: List[Tuple[Optional[str], Optional[str]]] = []
        offset = 0
        blocks = len(data) // 16
        # Determine number of sectors and their sizes
        # For sizes > 1024 we treat like 4K; additional sizes fall back
        if len(data) == 1024:
            sector_sizes = [4] * 16
        elif len(data) == 4096:
            sector_sizes = [4] * 32 + [16] * 8
        else:
            # approximate by dividing blocks into 4 block sectors
            sector_count = blocks // 4
            sector_sizes = [4] * sector_count
        for size in sector_sizes:
            # trailer block index
            trailer_index = offset + (size - 1)
            block = data[trailer_index * 16:(trailer_index + 1) * 16]
            if len(block) < 16:
                keys.append((None, None))
            else:
                key_a = block[0:6].hex()
                key_b = block[10:16].hex()
                keys.append((key_a, key_b))
            offset += size
        return keys


# Register strategy on import
StrategyRegistry.register(RawFormatStrategy())