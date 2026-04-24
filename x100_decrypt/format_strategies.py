"""
Pluggable format strategies for MIFARE Classic dump normalisation.

This module defines a small hierarchy of strategy classes used to
recognise and normalise card dumps exported by different tools.  Each
strategy implements two methods:

``can_handle(data: bytes) -> bool``
    Return ``True`` if the strategy is capable of parsing the given
    byte sequence.  Strategies should perform inexpensive checks here
    (e.g. inspecting magic bytes) and avoid raising exceptions.

``normalize(data: bytes, strict: bool = True) -> MifareClassicDump``
    Parse the provided bytes into a canonical representation.  When
    ``strict`` is ``True`` strategies must raise an error on any
    inconsistency.  When ``strict`` is ``False`` strategies may try to
    pad or truncate the input to salvage as much data as possible.

The :class:`StrategyRegistry` collects registered strategies in the
order they are added.  :func:`get_strategy` returns the first strategy
whose ``can_handle`` method returns ``True``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import struct
from typing import TYPE_CHECKING, List, Optional, Tuple

if TYPE_CHECKING:
    from .engine import MifareClassicDump


class FormatStrategy(ABC):
    """Abstract base class for dump format strategies."""

    name: str = "unnamed"

    @abstractmethod
    def can_handle(self, data: bytes) -> bool:
        """Return True if this strategy recognises the input bytes."""
        raise NotImplementedError

    @abstractmethod
    def normalize(self, data: bytes, strict: bool = True) -> 'MifareClassicDump':
        """Normalise the input into a MifareClassicDump.

        When ``strict`` is True the implementation must raise an error if
        the input does not conform to the expected structure.  When
        ``False`` the strategy may attempt to pad or truncate the
        payload.
        """
        raise NotImplementedError


class StrategyRegistry:
    """Registry of available strategies.

    Strategies register themselves by instantiating their class and
    passing the instance to :meth:`register`.  The order of
    registration determines the order in which strategies are
    considered by :func:`get_strategy`.
    """

    _registry: List[FormatStrategy] = []

    @classmethod
    def register(cls, strategy: FormatStrategy) -> None:
        cls._registry.append(strategy)

    @classmethod
    def strategies(cls) -> List[FormatStrategy]:
        return list(cls._registry)


def get_strategy(data: bytes) -> FormatStrategy:
    """Return the first registered strategy that claims the input.

    Raises
    ------
    ValueError
        If no strategy recognises the input.
    """
    for strat in StrategyRegistry.strategies():
        try:
            if strat.can_handle(data):
                return strat
        except Exception:
            continue
    raise ValueError("No strategy can handle the provided data")


class RawFormatStrategy(FormatStrategy):
    """Parse raw .mfd/.bin dumps with no proprietary header."""

    name = "raw"

    def can_handle(self, data: bytes) -> bool:
        return len(data) >= 16 and (len(data) % 16 == 0)

    def normalize(self, data: bytes, strict: bool = True) -> 'MifareClassicDump':
        if not data:
            raise ValueError("Empty dump")
        payload = data
        if len(payload) % 16 != 0:
            if strict:
                raise ValueError(f"Payload length {len(payload)} is not multiple of 16")
            missing = 16 - (len(payload) % 16)
            payload += b"\x00" * missing
        uid: Optional[str] = None
        if len(payload) >= 4:
            uid = payload[0:4].hex()
        keys = self._extract_keys(payload)
        from .engine import MifareClassicDump  # avoid cycle
        return MifareClassicDump(uid=uid, data=payload, keys=keys, size=len(payload))

    def _extract_keys(self, data: bytes) -> List[Tuple[Optional[str], Optional[str]]]:
        keys: List[Tuple[Optional[str], Optional[str]]] = []
        blocks = len(data) // 16
        if len(data) == 1024:
            sector_sizes = [4] * 16
        elif len(data) == 4096:
            sector_sizes = [4] * 32 + [16] * 8
        else:
            sector_count = blocks // 4
            sector_sizes = [4] * sector_count
        offset = 0
        for size in sector_sizes:
            trailer_index = offset + (size - 1)
            block = data[trailer_index * 16:(trailer_index + 1) * 16]
            if len(block) < 16:
                keys.append((None, None))
            else:
                key_a = block[0:6].hex()
                key_b = block[10:16].hex()
                if key_a in ("000000000000", "ffffffffffff"):
                    key_a = None
                if key_b in ("000000000000", "ffffffffffff"):
                    key_b = None
                keys.append((key_a, key_b))
            offset += size
        return keys


class X100FormatStrategy(FormatStrategy):
    """Parse the proprietary X100/CopyKey export format."""

    name = "x100"
    _HEADER_STRUCT = struct.Struct(">4sBBHI")
    _MAGIC = b"X100"

    def __init__(self, header_magic: Optional[bytes] = None, header_struct: Optional[struct.Struct] = None) -> None:
        self.magic = header_magic or self._MAGIC
        self.header_struct = header_struct or self._HEADER_STRUCT

    def can_handle(self, data: bytes) -> bool:
        return len(data) >= self.header_struct.size and data.startswith(self.magic)

    def normalize(self, data: bytes, strict: bool = True) -> 'MifareClassicDump':
        if not self.can_handle(data):
            raise ValueError("Data does not appear to be an X100 dump")
        header_size = self.header_struct.size
        magic, ver_major, ver_minor, header_len, payload_len = self.header_struct.unpack_from(data, 0)
        if magic != self.magic:
            raise ValueError(f"Unexpected magic {magic!r}")
        if header_len < header_size:
            if strict:
                raise ValueError(f"Header length {header_len} too small")
            header_len = header_size
        payload_offset = header_len
        available = len(data) - payload_offset
        if payload_len == 0 or payload_len > available:
            if strict:
                raise ValueError(
                    f"Payload length {payload_len} invalid; only {available} bytes remain after header"
                )
            payload_len = available
        payload = data[payload_offset:payload_offset + payload_len]
        if len(payload) % 16 != 0:
            if strict:
                raise ValueError("Payload length is not a multiple of 16 bytes")
            missing = 16 - (len(payload) % 16)
            payload += b"\x00" * missing
        uid: Optional[str] = None
        raw = RawFormatStrategy()
        keys = raw._extract_keys(payload)
        from .engine import MifareClassicDump  # avoid cycle
        return MifareClassicDump(uid=uid, data=payload, keys=keys, size=len(payload))


# Register strategies in deterministic order: proprietary first, then raw fallback
StrategyRegistry.register(X100FormatStrategy())
StrategyRegistry.register(RawFormatStrategy())

__all__ = [
    "FormatStrategy",
    "StrategyRegistry",
    "get_strategy",
    "RawFormatStrategy",
    "X100FormatStrategy",
]