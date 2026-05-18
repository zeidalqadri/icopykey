"""External NFC reader interface for raw auth trace collection.

The CopyKEY/X100 device abstracts away the raw MIFARE authentication
protocol — encrypted nonces, NACKs, and parity bits are not exposed
through its HID interface.  For full key recovery (darkside attack,
nested attack), an external NFC reader that CAN capture raw auth
traces is required.

Supported readers:
    - PC/SC (pyscard): ACR122U, SCL3711, etc.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("copykey_cli.nfc_reader")


class NfcReader(ABC):
    """Abstract base for NFC readers capable of raw MIFARE auth capture."""

    @abstractmethod
    def connect(self) -> bool:
        """Open connection to the reader."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the reader."""

    @abstractmethod
    def is_connected(self) -> bool:
        """Return True if the reader is connected."""

    @abstractmethod
    def get_card_uid(self) -> bytes | None:
        """Detect and return the card's 4-byte UID, or None."""

    @abstractmethod
    def authenticate(self, block: int, key: bytes, key_type: int = 0x60) -> bool:
        """Authenticate to a block with the given key.

        Returns True if authentication succeeds.
        """

    @abstractmethod
    def read_block(self, block: int) -> bytes | None:
        """Read a single 16-byte block (requires prior authentication)."""

    def read_sector(self, sector: int, key: bytes, key_type: int = 0x60) -> dict[str, Any] | None:
        """Read all blocks in a sector (convenience).

        Returns dict with 'blocks' (list of 16-byte bytes) or None.
        """
        blocks: list[bytes] = []
        first_block = sector * 4
        for offset in range(4):
            blk = first_block + offset
            if not self.authenticate(blk, key, key_type):
                return None
            data = self.read_block(blk)
            if data is None:
                return None
            blocks.append(data)
        return {"blocks": blocks}

    def collect_encrypted_nonces(
        self,
        block: int,
        num_attempts: int = 200,
    ) -> list[bytes]:
        """Collect encrypted tag nonces from failed auth attempts.

        Attempts authentication with a deliberately wrong key and records
        the encrypted nonce from each attempt.  Returns a list of 4-byte
        encrypted nonces.

        NOTE: This requires a reader firmware or driver that exposes the
        raw encrypted nonce.  Most PC/SC readers do NOT expose this data
        through the standard APDU interface — you may need a modified
        firmware or a lower-level library.
        """
        _ = block, num_attempts
        logger.warning(
            "collect_encrypted_nonces: not implemented — requires "
            "reader firmware that exposes raw auth nonces"
        )
        return []


class PcscReader(NfcReader):
    """PC/SC-based NFC reader (ACR122U, SCL3711, etc.) via pyscard.

    The standard APDU interface does NOT expose raw MIFARE auth nonces.
    This class provides basic MIFARE classic sector read/write but cannot
    collect encrypted nonces needed for darkside/nested attacks without
    additional firmware modifications.
    """

    def __init__(self) -> None:
        self._connected = False
        self._card_connection: Any = None

    @property
    def available(self) -> bool:
        try:
            import smartcard  # noqa: F401
            return True
        except ImportError:
            return False

    def connect(self) -> bool:
        if not self.available:
            logger.warning("pyscard not installed — cannot use PC/SC reader")
            return False
        try:
            from smartcard.System import readers
            from smartcard.CardConnection import CardConnection

            reader_list = readers()
            if not reader_list:
                logger.warning("No PC/SC readers found")
                return False
            conn = reader_list[0].createConnection()
            conn.connect(CardConnection.T0_protocol)
            self._card_connection = conn
            self._connected = True
            logger.info("Connected to PC/SC reader: %s", reader_list[0])
            return True
        except Exception as e:
            logger.error("PC/SC connect failed: %s", e)
            return False

    def disconnect(self) -> None:
        if self._card_connection:
            try:
                self._card_connection.disconnect()
            except Exception:
                pass
        self._connected = False
        self._card_connection = None

    def is_connected(self) -> bool:
        return self._connected

    def get_card_uid(self) -> bytes | None:
        if not self._card_connection:
            return None
        try:
            from smartcard.CardConnection import CardConnection

            data, _ = self._card_connection.transmit(
                [0xFF, 0xCA, 0x00, 0x00, 0x00]
            )
            if data and len(data) >= 4:
                return bytes(data[:4])
            return None
        except Exception as e:
            logger.error("get_card_uid failed: %s", e)
            return None

    def authenticate(self, block: int, key: bytes, key_type: int = 0x60) -> bool:
        if not self._card_connection:
            return False
        try:
            # APDU: FF 86 00 00 05 00 00 SS BB KK KK KK KK KK
            # SS = 1 byte (key type + key number), BB = block, KK... = key
            apdu = [
                0xFF, 0x86, 0x00, 0x00, 0x05,
                0x01, 0x00, block, key_type,
            ]
            apdu += list(key[:6])
            apdu.append(0x00)
            data, sw1, sw2 = self._card_connection.transmit(apdu)
            return sw1 == 0x90 and sw2 == 0x00
        except Exception as e:
            logger.debug("auth failed: %s", e)
            return False

    def read_block(self, block: int) -> bytes | None:
        if not self._card_connection:
            return None
        try:
            apdu = [0xFF, 0xB0, 0x00, block, 0x10]
            data, sw1, sw2 = self._card_connection.transmit(apdu)
            if sw1 == 0x90 and sw2 == 0x00:
                return bytes(data)
            return None
        except Exception as e:
            logger.debug("read_block failed: %s", e)
            return None


def create_reader(kind: str = "auto") -> NfcReader | None:
    """Factory: create the best available NFC reader.

    Parameters
    ----------
    kind : str
        ``"pcsc"`` to force PC/SC, ``"auto"`` to try available readers.

    Returns
    -------
    NfcReader or None if no reader is available.
    """
    if kind == "auto":
        pcsc = PcscReader()
        if pcsc.available:
            return pcsc
        return None
    if kind == "pcsc":
        return PcscReader()
    logger.warning("Unknown reader kind: %s", kind)
    return None
