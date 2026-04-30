"""High-level card operations combining device commands into workflows."""

from __future__ import annotations

import logging
import secrets
from typing import Any

from .constants import DEFAULT_KEYS
from .device import CopyKeyDevice
from .mifare_data import MifareCard

logger = logging.getLogger("copykey_cli.card_ops")


class CardOperations:
    """High-level card operations combining device commands into workflows."""

    def __init__(self, device: CopyKeyDevice) -> None:
        self.device = device
        self.current_card: MifareCard | None = None

    def read_card_info(self) -> dict[str, Any] | None:
        return self.device.read_card_info()

    def decode_card(
        self, custom_keys: list[bytes] | None = None, show_progress: bool = True
    ) -> MifareCard | None:
        info = self.read_card_info()
        if not info:
            logger.error("Failed to read card info")
            return None
        card = MifareCard(
            uid=info["uid"], sak=info["sak"], atqa=info["atqa"], card_type=info["card_type"]
        )
        all_keys = list(DEFAULT_KEYS) + (custom_keys or [])
        locked_sectors: list[int] = []

        if show_progress:
            logger.info("[*] Decoding card UID: %s (%s)", card.uid_hex, card.card_type)
            logger.info("[*] Trying %d keys...", len(all_keys))

        for i in range(card.num_sectors):
            found = False
            for key in all_keys:
                sector = self.device.read_sector(i, key, key_type=0)
                if sector:
                    sector.index = i
                    card.set_sector(i, sector)
                    if show_progress:
                        logger.info("    Sector %2d OK (KeyA: %s)", i, key.hex().upper())
                    found = True
                    break
                sector = self.device.read_sector(i, key, key_type=1)
                if sector:
                    sector.index = i
                    card.set_sector(i, sector)
                    if show_progress:
                        logger.info("    Sector %2d OK (KeyB: %s)", i, key.hex().upper())
                    found = True
                    break
            if not found:
                locked_sectors.append(i)
                if show_progress:
                    logger.warning("    Sector %2d LOCKED - need manual key", i)

        self.current_card = card
        if locked_sectors and show_progress:
            logger.warning(
                "[!] %d sector(s) remain locked: %s", len(locked_sectors), locked_sectors
            )
        return card

    def encrypt_card_data(
        self,
        card: MifareCard | None = None,
        new_key_a: bytes | None = None,
        new_key_b: bytes | None = None,
        random_keys: bool = False,
        sectors: list[int] | None = None,
    ) -> bool:
        card = card or self.current_card
        if not card:
            logger.error("No card data available")
            return False
        if sectors is None:
            sectors = list(range(1, card.num_sectors))
        logger.info("[*] Encrypting %d sector(s)...", len(sectors))
        for i in sectors:
            sector = card.get_sector(i)
            if not sector:
                continue
            if random_keys:
                sector_key_a = secrets.token_bytes(6)
                sector_key_b = secrets.token_bytes(6)
            else:
                sector_key_a = new_key_a or sector.key_a
                sector_key_b = new_key_b or sector.key_b
            sector.update_trailer(key_a=sector_key_a, access_bits=sector.access_bits, key_b=sector_key_b)
            card.set_sector(i, sector)
        logger.info("[+] Card data encrypted with new keys.")
        return True

    def write_full_card(
        self, card: MifareCard | None = None, transport_key: bytes | None = None
    ) -> bool:
        card = card or self.current_card
        if not card:
            logger.error("No card data to write")
            return False
        transport_key = transport_key or b"\xff" * 6
        logger.info("[*] Writing card...")
        success_count = 0
        total = card.num_sectors
        for i in range(total):
            sector = card.get_sector(i)
            if not sector:
                continue
            auth_key = sector.key_a if i > 0 else transport_key
            if self.device.write_sector(i, sector, auth_key):
                success_count += 1
                logger.info("    Sector %2d written successfully", i)
            else:
                logger.error("[-] Failed writing sector %d", i)
        logger.info("[+] Card written: %d/%d sectors successful", success_count, total)
        return success_count == total
