"""
Card Data Encryption Module
NO NETWORK COMMUNICATION - Local encryption only
"""
from typing import List, Optional
from Crypto.Random import get_random_bytes
import secrets

from .mifare_crypto import MifareCard, MifareSector


def generate_random_mifare_key() -> bytes:
    return secrets.token_bytes(6)


def generate_key_set(num_keys: int = 16) -> List[bytes]:
    return [generate_random_mifare_key() for _ in range(num_keys)]


def calculate_access_bits(read_only: bool = False) -> bytes:
    if read_only:
        return b'\x78\x77\x88\x00'
    return b'\x78\x77\x88\x00'


class CardEncryptor:
    DUMP_KEY_A = b'\x00' * 6
    DUMP_KEY_B = b'\x00' * 6

    def encrypt_sector(
        self,
        sector_data: bytes,
        key_a: bytes,
        key_b: bytes,
        access_bits: bytes = None,
    ) -> bytes:
        if access_bits is None:
            access_bits = calculate_access_bits(read_only=False)
        if len(sector_data) < 64:
            raise ValueError("Sector data must be at least 64 bytes")
        trailer = key_a + access_bits + key_b
        encrypted = bytearray(sector_data)
        encrypted[48:64] = trailer
        return bytes(encrypted)

    def encrypt_sector_object(
        self,
        sector: MifareSector,
        new_key_a: Optional[bytes] = None,
        new_key_b: Optional[bytes] = None,
        access_bits: Optional[bytes] = None,
        random_keys: bool = False,
    ) -> MifareSector:
        if random_keys:
            ka = secrets.token_bytes(6)
            kb = secrets.token_bytes(6)
        else:
            ka = new_key_a if new_key_a is not None else sector.key_a
            kb = new_key_b if new_key_b is not None else sector.key_b
        sector.update_trailer(key_a=ka, access_bits=access_bits, key_b=kb)
        return sector

    def encrypt_full_card(
        self,
        card: MifareCard,
        key_strategy: str = 'random_per_sector',
        single_key_a: Optional[bytes] = None,
        single_key_b: Optional[bytes] = None,
        sectors: Optional[List[int]] = None,
    ) -> MifareCard:
        if sectors is None:
            sectors = list(range(1, card.num_sectors))
        for i in sectors:
            sector = card.get_sector(i)
            if not sector:
                continue
            if key_strategy == 'random_per_sector':
                sector = self.encrypt_sector_object(sector, random_keys=True)
            elif key_strategy == 'single_key':
                sector = self.encrypt_sector_object(
                    sector,
                    new_key_a=single_key_a or self.DUMP_KEY_A,
                    new_key_b=single_key_b or self.DUMP_KEY_B,
                )
            elif key_strategy == 'none':
                sector = self.encrypt_sector_object(
                    sector,
                    new_key_a=sector.key_a,
                    new_key_b=sector.key_b,
                )
            card.set_sector(i, sector)
        return card

    def dump_card_sectors(self, card: MifareCard) -> MifareCard:
        for i in range(1, card.num_sectors):
            sector = card.get_sector(i)
            if sector:
                self.encrypt_sector_object(
                    sector,
                    new_key_a=self.DUMP_KEY_A,
                    new_key_b=self.DUMP_KEY_B,
                    access_bits=calculate_access_bits(),
                )
        return card
