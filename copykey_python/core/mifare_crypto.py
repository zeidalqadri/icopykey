"""
Mifare Crypto-1 Implementation
NO NETWORK COMMUNICATION - Pure cryptographic algorithms
"""
from typing import List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Crypto1:
    """
    Implementation of Mifare Classic Crypto-1 cipher.
    Based on open-source research (libnfc, mfoc, crapto1).

    Currently a structural skeleton — the full LFSR keystream generator
    requires the 48-bit LFSR feedback polynomial and filter function
    from the original NXP Crypto-1 specification.
    """

    LFSR_MASK = (1 << 48) - 1

    def __init__(self):
        self.lfsr: int = 0
        self._uid: Optional[bytes] = None
        self._nt: Optional[int] = None

    def init(self, key: bytes) -> None:
        if len(key) != 6:
            raise ValueError("Key must be 6 bytes")
        self.lfsr = int.from_bytes(key, 'big')

    def init_with_tag(self, key: bytes, uid: bytes, nt: bytes) -> None:
        self.init(key)
        self._uid = uid
        self._nt = int.from_bytes(nt, 'little') & 0xFFFFFFFF
        uid_val = int.from_bytes(uid, 'little') & 0xFFFFFFFF
        self.lfsr ^= uid_val
        self.lfsr &= self.LFSR_MASK
        for _ in range(32):
            self._lfsr_clock()

    def _lfsr_clock(self) -> int:
        fb = (
            ((self.lfsr >> 0) & 1)
            ^ ((self.lfsr >> 5) & 1)
            ^ ((self.lfsr >> 9) & 1)
            ^ ((self.lfsr >> 10) & 1)
            ^ ((self.lfsr >> 12) & 1)
            ^ ((self.lfsr >> 14) & 1)
            ^ ((self.lfsr >> 15) & 1)
            ^ ((self.lfsr >> 17) & 1)
            ^ ((self.lfsr >> 19) & 1)
            ^ ((self.lfsr >> 24) & 1)
            ^ ((self.lfsr >> 25) & 1)
            ^ ((self.lfsr >> 27) & 1)
            ^ ((self.lfsr >> 29) & 1)
            ^ ((self.lfsr >> 35) & 1)
            ^ ((self.lfsr >> 39) & 1)
            ^ ((self.lfsr >> 41) & 1)
            ^ ((self.lfsr >> 43) & 1)
        )
        self.lfsr = ((self.lfsr << 1) | fb) & self.LFSR_MASK
        return fb

    def _filter_function(self) -> int:
        x = self.lfsr
        return (
            ((x >> 0) & 1)
            ^ ((x >> 2) & 1)
            ^ ((x >> 5) & 1)
            ^ ((x >> 7) & 1)
            ^ ((x >> 8) & 1)
            ^ ((x >> 11) & 1)
            ^ ((x >> 13) & 1)
            ^ ((x >> 16) & 1)
            ^ ((x >> 18) & 1)
            ^ ((x >> 20) & 1)
            ^ ((x >> 22) & 1)
            ^ ((x >> 23) & 1)
            ^ ((x >> 26) & 1)
            ^ ((x >> 30) & 1)
            ^ ((x >> 31) & 1)
            ^ ((x >> 34) & 1)
            ^ ((x >> 36) & 1)
            ^ ((x >> 38) & 1)
            ^ ((x >> 40) & 1)
            ^ ((x >> 42) & 1)
            ^ ((x >> 44) & 1)
            ^ ((x >> 46) & 1)
            ^ ((x >> 47) & 1)
        )

    def generate_keystream(self, length: int) -> bytes:
        ks = bytearray()
        for _ in range(length):
            byte_val = 0
            for _ in range(8):
                byte_val = (byte_val << 1) | self._filter_function()
                self._lfsr_clock()
            ks.append(byte_val)
        return bytes(ks)

    def encrypt(self, data: bytes) -> bytes:
        ks = self.generate_keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)

    def authenticate(self, uid: bytes, block: int, key: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        nt = int.from_bytes(uid[:4], 'little') ^ block
        self.init_with_tag(key, uid, nt.to_bytes(4, 'little'))
        nr = self.generate_keystream(4)
        response = self.generate_keystream(4)
        return (nr, response)

    @staticmethod
    def crack_key(nonce: bytes, response: bytes, uid: bytes) -> Optional[bytes]:
        return None


class AccessCondition(Enum):
    NEVER = 0
    KEY_A = 1
    KEY_B = 2
    KEY_A_OR_B = 3
    ALWAYS = 4


@dataclass
class SectorKeyInfo:
    key_a: str = "ffffffffffff"
    key_b: str = "ffffffffffff"
    access_bits: str = "ff078069"
    known: bool = False


@dataclass
class MifareSector:
    index: int
    blocks: List[bytes] = field(default_factory=lambda: [b'\x00' * 16] * 4)
    key_a: bytes = b'\xff' * 6
    key_b: bytes = b'\xff' * 6
    access_bits: bytes = b'\xff\x07\x80\x69'

    def __post_init__(self):
        if len(self.blocks) != 4:
            self.blocks = [b'\x00' * 16] * 4
        if self.key_a == b'\xff' * 6 and len(self.blocks[3]) == 16:
            trailer = self.blocks[3]
            self.key_a = trailer[0:6]
            self.access_bits = trailer[6:10]
            self.key_b = trailer[10:16]

    def from_blocks(self, blocks: List[bytes]) -> 'MifareSector':
        if len(blocks) != 4:
            raise ValueError("Sector must have exactly 4 blocks")
        self.blocks = blocks
        trailer = blocks[3]
        if len(trailer) >= 16:
            self.key_a = trailer[0:6]
            self.access_bits = trailer[6:10]
            self.key_b = trailer[10:16]
        return self

    def update_trailer(self, key_a: bytes = None, access_bits: bytes = None, key_b: bytes = None) -> None:
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

    def to_dict(self) -> dict:
        return {
            'index': self.index,
            'key_a': self.key_a.hex(),
            'key_b': self.key_b.hex(),
            'access_bits': self.access_bits.hex(),
            'blocks': [blk.hex() for blk in self.blocks]
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'MifareSector':
        sector = cls(index=data['index'])
        sector.key_a = bytes.fromhex(data['key_a'])
        sector.key_b = bytes.fromhex(data['key_b'])
        sector.access_bits = bytes.fromhex(data['access_bits'])
        sector.blocks = [bytes.fromhex(b) for b in data['blocks']]
        return sector


@dataclass
class MifareCard:
    uid: bytes
    sak: int
    atqa: bytes
    card_type: str = "Mifare Classic 1K"
    sectors: List[MifareSector] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    modified: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self):
        if not self.sectors:
            if self.sak == 0x18:
                self.card_type = "Mifare Classic 4K"
                self.sectors = [MifareSector(i) for i in range(40)]
            else:
                self.card_type = "Mifare Classic 1K"
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

    def get_sector(self, index: int) -> Optional[MifareSector]:
        if 0 <= index < len(self.sectors):
            return self.sectors[index]
        return None

    def set_sector(self, index: int, sector: MifareSector) -> None:
        if 0 <= index < len(self.sectors):
            self.sectors[index] = sector
            self.modified = datetime.now().isoformat()
        else:
            raise IndexError(f"Sector index {index} out of range")

    def to_dict(self) -> dict:
        return {
            'uid': self.uid.hex(),
            'sak': self.sak,
            'atqa': self.atqa.hex(),
            'card_type': self.card_type,
            'created': self.created,
            'modified': self.modified,
            'sectors': [sec.to_dict() for sec in self.sectors]
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'MifareCard':
        card = cls(
            uid=bytes.fromhex(data['uid']),
            sak=data['sak'],
            atqa=bytes.fromhex(data['atqa']),
            card_type=data.get('card_type', 'Mifare Classic 1K'),
            created=data.get('created', datetime.now().isoformat()),
            modified=data.get('modified', datetime.now().isoformat())
        )
        card.sectors = [MifareSector.from_dict(sec) for sec in data['sectors']]
        return card


DEFAULT_MIFARE_KEYS: List[bytes] = [
    b'\xff\xff\xff\xff\xff\xff',
    b'\x00\x00\x00\x00\x00\x00',
    b'\xa0\xa1\xa2\xa3\xa4\xa5',
    b'\xb0\xb1\xb2\xb3\xb4\xb5',
    b'\x4d\x3a\x99\xc3\x51\xdd',
    b'\x1a\x98\x2c\x7e\x45\x9a',
    b'\xd3\xf7\xd3\xf7\xd3\xf7',
    b'\xaa\xbb\xcc\xdd\xee\xff',
    b'\x11\x22\x33\x44\x55\x66',
    b'\x65\x43\x21\xfe\xdc\xba',
]
