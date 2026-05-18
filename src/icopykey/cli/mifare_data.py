"""Card data structures: MIFARE Classic sectors, NTAG pages, DESFire stubs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class MifareSector:
    """A MIFARE Classic sector.

    Most sectors have 4 blocks (16 bytes each).  4K large sectors
    (indices 32-39) have 16 blocks each; the trailer is block 15.
    """

    index: int
    num_blocks: int = 4
    blocks: list[bytes] = field(default_factory=lambda: [b"\x00" * 16] * 4)
    key_a: bytes = field(default_factory=lambda: b"\xff" * 6)
    key_b: bytes = field(default_factory=lambda: b"\xff" * 6)
    access_bits: bytes = field(default_factory=lambda: b"\xff\x07\x80\x69")

    def __post_init__(self) -> None:
        expected = self.num_blocks
        if len(self.blocks) != expected:
            self.blocks = [b"\x00" * 16] * expected
        trailer = self.blocks[-1]
        if len(trailer) == 16:
            if self.key_a == b"\xff" * 6:
                self.key_a = trailer[0:6]
            if self.access_bits == b"\xff\x07\x80\x69":
                self.access_bits = trailer[6:10]
            if self.key_b == b"\xff" * 6:
                self.key_b = trailer[10:16]

    @classmethod
    def from_blocks(cls, blocks: list[bytes]) -> "MifareSector":
        n = len(blocks)
        if n not in (4, 16):
            raise ValueError(f"Sector must have 4 or 16 blocks, got {n}")
        trailer = blocks[-1]
        return cls(
            index=0,
            num_blocks=n,
            blocks=list(blocks),
            key_a=trailer[0:6] if len(trailer) >= 16 else b"\xff" * 6,
            access_bits=trailer[6:10] if len(trailer) >= 16 else b"\xff\x07\x80\x69",
            key_b=trailer[10:16] if len(trailer) >= 16 else b"\xff" * 6,
        )

    def update_trailer(
        self,
        key_a: bytes | None = None,
        access_bits: bytes | None = None,
        key_b: bytes | None = None,
    ) -> None:
        trailer = bytearray(self.blocks[3])
        if key_a is not None:
            if len(key_a) != 6:
                raise ValueError("Key A must be 6 bytes")
            trailer[0:6] = key_a
            self.key_a = key_a
        if access_bits is not None:
            if len(access_bits) != 4:
                raise ValueError("Access bits must be 4 bytes")
            trailer[6:10] = access_bits
            self.access_bits = access_bits
        if key_b is not None:
            if len(key_b) != 6:
                raise ValueError("Key B must be 6 bytes")
            trailer[10:16] = key_b
            self.key_b = key_b
        self.blocks[3] = bytes(trailer)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "num_blocks": self.num_blocks,
            "key_a": self.key_a.hex(),
            "key_b": self.key_b.hex(),
            "access_bits": self.access_bits.hex(),
            "blocks": [blk.hex() for blk in self.blocks],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MifareSector":
        blocks = [bytes.fromhex(b) for b in data["blocks"]]
        n = data.get("num_blocks", len(blocks))
        sector = cls(index=data["index"], num_blocks=n)
        sector.key_a = bytes.fromhex(data["key_a"])
        sector.key_b = bytes.fromhex(data["key_b"])
        sector.access_bits = bytes.fromhex(data["access_bits"])
        sector.blocks = blocks
        return sector


@dataclass
class MifareCard:
    """A complete MIFARE Classic card dump (1K or 4K)."""

    uid: bytes
    sak: int
    atqa: bytes
    card_type: str = "MIFARE Classic 1K"
    sectors: list[MifareSector] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    modified: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self) -> None:
        if not self.sectors:
            if self.sak == 0x18:
                self.card_type = "MIFARE Classic 4K"
                self.sectors = [
                    MifareSector(i, num_blocks=16) if i >= 32 else MifareSector(i)
                    for i in range(40)
                ]
            else:
                self.sectors = [MifareSector(i) for i in range(16)]

    @property
    def num_sectors(self) -> int:
        return len(self.sectors)

    @property
    def uid_hex(self) -> str:
        return self.uid.hex().upper()

    def full_dump(self) -> bytes:
        dump = self.uid
        for sec in self.sectors:
            for blk in sec.blocks:
                dump += blk
        return dump

    def get_sector(self, index: int) -> MifareSector | None:
        if 0 <= index < len(self.sectors):
            return self.sectors[index]
        return None

    def set_sector(self, index: int, sector: MifareSector) -> None:
        if 0 <= index < len(self.sectors):
            self.sectors[index] = sector
            self.modified = datetime.now().isoformat()
        else:
            raise IndexError(f"Sector index {index} out of range")

    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid.hex(),
            "sak": self.sak,
            "atqa": self.atqa.hex(),
            "card_type": self.card_type,
            "created": self.created,
            "modified": self.modified,
            "sectors": [sec.to_dict() for sec in self.sectors],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MifareCard":
        card = cls(
            uid=bytes.fromhex(data["uid"]),
            sak=data["sak"],
            atqa=bytes.fromhex(data["atqa"]),
            card_type=data.get("card_type", "MIFARE Classic 1K"),
            created=data.get("created", datetime.now().isoformat()),
            modified=data.get("modified", datetime.now().isoformat()),
        )
        card.sectors = [MifareSector.from_dict(sec) for sec in data["sectors"]]
        return card


# ── NTAG / Ultralight ──────────────────────────────────────────────

NTAG_PAGE_COUNTS: dict[str, int] = {
    "NTAG213": 45,    # pages 0-44, 180 bytes
    "NTAG215": 135,   # pages 0-134, 540 bytes
    "NTAG216": 231,   # pages 0-230, 924 bytes
}

# Typical page layout (NTAG213/215/216):
#   Pages 0-4:    Manufacturer block (UID, serial, lock bytes)
#   Pages 4-39:   User memory (configurable via capability container)
#   Page 40:      Capability container (tag type, memory size)
#   Pages 41-42:  Reserved / config
#   Page 43:      Password (if PWD/PACK auth enabled)
#   Page 44:      PACK / mirror


@dataclass
class NtagCard:
    """NTAG / Ultralight EV1 card: pages of 4 bytes each."""

    uid: bytes
    pages: list[bytes] = field(default_factory=list)
    ntag_type: str = "NTAG213"
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    modified: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def uid_hex(self) -> str:
        return self.uid.hex().upper()

    @property
    def num_pages(self) -> int:
        return NTAG_PAGE_COUNTS.get(self.ntag_type, 45)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid.hex(),
            "card_type": f"NTAG/{self.ntag_type}",
            "ntag_type": self.ntag_type,
            "created": self.created,
            "modified": self.modified,
            "pages": [p.hex() for p in self.pages],
        }

    @classmethod
    def from_pages(cls, uid: bytes, pages: list[bytes]) -> "NtagCard":
        cap_container = pages[40] if len(pages) > 40 else b"\x00" * 4
        mem_size = cap_container[2] if len(cap_container) > 2 else 0
        if mem_size >= 0x12:
            ntag_type = "NTAG216"
        elif mem_size >= 0x0E:
            ntag_type = "NTAG215"
        else:
            ntag_type = "NTAG213"
        return cls(uid=uid, pages=pages, ntag_type=ntag_type)


# ── DESFire (stub) ──────────────────────────────────────────────────


@dataclass
class DesfireCard:
    """DESFire / DESFire EV1 / EV2 card (stub — not yet implemented)."""

    uid: bytes
    card_type: str = "DESFire"
    created: str = field(default_factory=lambda: datetime.now().isoformat())
