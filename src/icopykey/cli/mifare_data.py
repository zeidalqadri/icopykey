"""MIFARE Classic data structures: sectors and cards."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class MifareSector:
    """A MIFARE Classic sector (4 blocks of 16 bytes each)."""

    index: int
    blocks: list[bytes] = field(default_factory=lambda: [b"\x00" * 16] * 4)
    key_a: bytes = field(default_factory=lambda: b"\xff" * 6)
    key_b: bytes = field(default_factory=lambda: b"\xff" * 6)
    access_bits: bytes = field(default_factory=lambda: b"\xff\x07\x80\x69")

    def __post_init__(self) -> None:
        if len(self.blocks) != 4:
            self.blocks = [b"\x00" * 16] * 4
        if len(self.blocks[3]) == 16:
            trailer = self.blocks[3]
            if self.key_a == b"\xff" * 6:
                self.key_a = trailer[0:6]
            if self.access_bits == b"\xff\x07\x80\x69":
                self.access_bits = trailer[6:10]
            if self.key_b == b"\xff" * 6:
                self.key_b = trailer[10:16]

    @classmethod
    def from_blocks(cls, blocks: list[bytes]) -> "MifareSector":
        if len(blocks) != 4:
            raise ValueError("Sector must have exactly 4 blocks")
        trailer = blocks[3]
        return cls(
            index=0,
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
            "key_a": self.key_a.hex(),
            "key_b": self.key_b.hex(),
            "access_bits": self.access_bits.hex(),
            "blocks": [blk.hex() for blk in self.blocks],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MifareSector":
        sector = cls(index=data["index"])
        sector.key_a = bytes.fromhex(data["key_a"])
        sector.key_b = bytes.fromhex(data["key_b"])
        sector.access_bits = bytes.fromhex(data["access_bits"])
        sector.blocks = [bytes.fromhex(b) for b in data["blocks"]]
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
                self.sectors = [MifareSector(i) for i in range(40)]
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
