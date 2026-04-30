"""Encrypted local storage for keys and cards."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from .mifare_data import MifareCard
from .vault import AESVault

logger = logging.getLogger("copykey_cli.library")


class LocalLibrary:
    """Encrypted local storage for keys and cards."""

    def __init__(self, data_dir: Path, vault_password: str | None = None) -> None:
        self.data_dir = data_dir
        self.vault: AESVault | None = None
        self.encrypted = bool(vault_password)
        if vault_password:
            try:
                self.vault = AESVault(vault_password)
            except ValueError as e:
                logger.warning("Vault initialization failed: %s", e)
                self.encrypted = False
        self.key_file = data_dir / ("keys.json.enc" if self.encrypted else "keys.json")
        self.card_file = data_dir / ("cards.json.enc" if self.encrypted else "cards.json")
        self.keys: dict[str, bytes] = {}
        self.cards: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        self.keys = {}
        self.cards = []
        if self.key_file.exists():
            try:
                plain = (
                    self.vault.decrypt(self.key_file.read_bytes())
                    if (self.encrypted and self.vault)
                    else self.key_file.read_text(encoding="utf-8")
                )
                self.keys = {k: bytes.fromhex(v) for k, v in json.loads(plain).items()}
                logger.info("Loaded %d keys from library", len(self.keys))
            except Exception as e:
                logger.error("[!] Failed to load key library: %s", e)
        if self.card_file.exists():
            try:
                plain = (
                    self.vault.decrypt(self.card_file.read_bytes())
                    if (self.encrypted and self.vault)
                    else self.card_file.read_text(encoding="utf-8")
                )
                self.cards = json.loads(plain)
                logger.info("Loaded %d cards from library", len(self.cards))
            except Exception as e:
                logger.error("[!] Failed to load card library: %s", e)

    def _save(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        key_data = json.dumps({k: v.hex() for k, v in self.keys.items()}, indent=2)
        card_data = json.dumps(self.cards, indent=2)
        if self.encrypted and self.vault:
            self.key_file.write_bytes(self.vault.encrypt(key_data))
            self.card_file.write_bytes(self.vault.encrypt(card_data))
        else:
            self.key_file.write_text(key_data, encoding="utf-8")
            self.card_file.write_text(card_data, encoding="utf-8")
        logger.debug("[+] Library saved.")

    def add_key(self, name: str, key: bytes) -> None:
        if len(key) != 6:
            raise ValueError("Key must be 6 bytes")
        self.keys[name] = key
        self._save()
        logger.info("[+] Added key '%s'", name)

    def remove_key(self, name: str) -> bool:
        if name in self.keys:
            del self.keys[name]
            self._save()
            logger.info("[+] Removed key '%s'", name)
            return True
        logger.warning("Key '%s' not found", name)
        return False

    def get_keys(self) -> list[bytes]:
        return list(self.keys.values())

    def add_card(self, card: MifareCard, name: str) -> str:
        card_id = f"card_{len(self.cards)}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        card_entry = {
            "id": card_id,
            "name": name,
            "uid": card.uid.hex(),
            "sak": card.sak,
            "atqa": card.atqa.hex(),
            "card_type": card.card_type,
            "created": card.created,
            "modified": card.modified,
            "sectors": [sec.to_dict() for sec in card.sectors],
        }
        self.cards.append(card_entry)
        self._save()
        logger.info("[+] Added card '%s' (ID: %s)", name, card_id)
        return card_id

    def get_card(self, card_id: str) -> dict[str, Any] | None:
        for card in self.cards:
            if card["id"] == card_id:
                return card
        return None

    def list_cards(self) -> list[dict[str, str]]:
        return [
            {"id": c["id"], "name": c["name"], "uid": c["uid"], "card_type": c["card_type"], "created": c["created"]}
            for c in self.cards
        ]

    def remove_card(self, card_id: str) -> bool:
        for i, card in enumerate(self.cards):
            if card["id"] == card_id:
                del self.cards[i]
                self._save()
                logger.info("[+] Removed card '%s'", card["name"])
                return True
        logger.warning("Card '%s' not found", card_id)
        return False

    def export_card(self, card_id: str, fmt: str = "json") -> bytes | None:
        card = self.get_card(card_id)
        if not card:
            return None
        if fmt == "json":
            return json.dumps(card, indent=2).encode("utf-8")
        return None

    def import_card(self, data: bytes, fmt: str = "json") -> str | None:
        try:
            if fmt == "json":
                card_data = json.loads(data.decode("utf-8"))
                if "uid" not in card_data:
                    logger.error("Imported card missing UID")
                    return None
                card = MifareCard.from_dict(card_data)
                name = card_data.get("name", f"Imported_{card.uid_hex}")
                return self.add_card(card, name)
        except Exception as e:
            logger.error("Import failed: %s", e)
        return None

    def search_cards(self, query: str) -> list[dict[str, str]]:
        q = query.lower()
        return [
            {"id": c["id"], "name": c["name"], "uid": c["uid"], "card_type": c["card_type"]}
            for c in self.cards
            if q in c["name"].lower() or q in c["uid"].lower()
        ]
