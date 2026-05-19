"""External NFC reader interface for raw auth trace collection.

The CopyKEY/X100 device abstracts away the raw MIFARE authentication
protocol — encrypted nonces, NACKs, and parity bits are not exposed
through its HID interface.  For full key recovery (darkside attack,
nested attack), an external NFC reader that CAN capture raw auth
traces is required.

Two layers are provided:

* :class:`NfcReader` / :class:`PcscReader` — high-level reader interface
  for authenticated sector reads via PC/SC APDUs.

* :class:`NonceSource` and its subclasses (:class:`LibNfcCLINonceSource`,
  :class:`NfcpyNonceSource`) — backends that capture encrypted MIFARE
  tag nonces suitable for feeding into :class:`NestedAttack` /
  :class:`DarksideAttack`.  Standard PC/SC APDUs do **not** expose raw
  encrypted nonces, so these backends shell out to libnfc tools
  (``mfcuk``/``mfoc``) or use a patched ``nfcpy`` build.

Supported readers / sources:
    - PC/SC (pyscard): ACR122U, SCL3711, etc. — auth + sector read.
    - libnfc CLI (``mfcuk``): nonce capture for darkside.
    - nfcpy (with a fork that exposes raw nonces): nonce capture.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("copykey_cli.nfc_reader")


# ── Nonce sources (libnfc / nfcpy adapters) ───────────────────────────────


class NonceSource(ABC):
    """A backend that captures raw encrypted MIFARE tag nonces.

    Designed to feed :class:`icopykey.cli.crypto1_attack.DarksideAttack`
    and :class:`NestedAttack`.  Each source is gated by an
    :attr:`available` property so callers can pick the best installed
    option at runtime.
    """

    name: str = "base"

    @property
    @abstractmethod
    def available(self) -> bool:
        """True if this source is usable (binary on PATH / library importable)."""

    @abstractmethod
    def collect(
        self,
        sector: int,
        *,
        key_type: int = 0x60,
        num: int = 256,
        known_key: bytes | None = None,
        timeout: float = 120.0,
    ) -> list[bytes]:
        """Collect up to ``num`` encrypted tag nonces from *sector*.

        Returns a list of 4-byte encrypted nonces (possibly empty).
        """


class LibNfcCLINonceSource(NonceSource):
    """Capture nonces by shelling out to ``mfcuk`` from the libnfc toolset.

    ``mfcuk -C -R <block>:<A|B>`` repeatedly attempts authentication and
    prints encrypted nonces to stdout.  We parse them out.  Requires
    ``mfcuk`` on ``$PATH``.
    """

    name = "libnfc-mfcuk"
    BINARY = "mfcuk"
    NONCE_RE = re.compile(r"Nt\s*=\s*0x([0-9A-Fa-f]{8})")

    @property
    def available(self) -> bool:
        return shutil.which(self.BINARY) is not None

    def collect(
        self,
        sector: int,
        *,
        key_type: int = 0x60,
        num: int = 256,
        known_key: bytes | None = None,
        timeout: float = 120.0,
    ) -> list[bytes]:
        if not self.available:
            return []
        block = sector * 4
        key_char = "A" if key_type == 0x60 else "B"
        cmd = [self.BINARY, "-C", "-R", f"{block}:{key_char}"]
        if known_key is not None and len(known_key) == 6:
            cmd += ["-k", known_key.hex().upper()]
        cmd += ["-s", str(num)]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("%s: %s", self.name, exc)
            return []
        if proc.returncode != 0:
            logger.warning(
                "%s exited %d: %s", self.name, proc.returncode, proc.stderr.strip()
            )
        nonces: list[bytes] = []
        for match in self.NONCE_RE.finditer(proc.stdout):
            try:
                nonces.append(bytes.fromhex(match.group(1)))
            except ValueError:
                continue
            if len(nonces) >= num:
                break
        logger.info("%s captured %d nonces for sector %d", self.name, len(nonces), sector)
        return nonces


class NfcpyNonceSource(NonceSource):
    """Capture nonces via ``nfcpy``.

    Standard upstream ``nfcpy`` does not expose raw MIFARE auth nonces
    through its high-level API, so this backend is a thin shim that
    detects availability and delegates to a user-supplied helper if one
    is found.  Patched forks (and some PN532 boards driven directly)
    can return raw nonces; in those cases the helper hooks in here.
    """

    name = "nfcpy"
    HELPER_ATTR = "_icopykey_capture_nonces"

    @property
    def available(self) -> bool:
        try:
            import nfc  # noqa: F401

            return True
        except ImportError:
            return False

    def collect(
        self,
        sector: int,
        *,
        key_type: int = 0x60,
        num: int = 256,
        known_key: bytes | None = None,
        timeout: float = 120.0,
    ) -> list[bytes]:
        if not self.available:
            return []
        try:
            import nfc
        except ImportError:
            return []

        helper = getattr(nfc, self.HELPER_ATTR, None)
        if helper is None:
            logger.warning(
                "nfcpy is installed but does not expose raw nonces. "
                "Attach a capture helper as nfc.%s(sector, key_type, num, known_key) "
                "or use the libnfc CLI backend instead.",
                self.HELPER_ATTR,
            )
            return []
        try:
            return list(
                helper(
                    sector=sector,
                    key_type=key_type,
                    num=num,
                    known_key=known_key,
                    timeout=timeout,
                )
            )
        except Exception as exc:  # pragma: no cover - depends on user helper
            logger.warning("%s helper raised: %s", self.name, exc)
            return []


# Order matters: prefer libnfc CLI (more reliable) over nfcpy shim.
_NONCE_SOURCE_CLASSES: tuple[type[NonceSource], ...] = (
    LibNfcCLINonceSource,
    NfcpyNonceSource,
)


def auto_nonce_source() -> NonceSource | None:
    """Return the first available :class:`NonceSource`, or None."""
    for cls in _NONCE_SOURCE_CLASSES:
        src = cls()
        if src.available:
            return src
    return None


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
        known_key: bytes | None = None,
        key_type: int = 0x60,
    ) -> list[bytes]:
        """Collect encrypted tag nonces from failed auth attempts.

        Delegates to whichever :class:`NonceSource` is available
        (``mfcuk`` via libnfc, or a patched ``nfcpy``).  Returns ``[]``
        if no source is installed — log message tells the user what to
        install.

        Standard PC/SC APDUs do not expose raw nonces; the external
        source typically drives an ACR122U / PN532 directly via libusb.
        """
        source = auto_nonce_source()
        if source is None:
            logger.warning(
                "collect_encrypted_nonces: no nonce source available. "
                "Install `mfcuk` (libnfc) or a patched `nfcpy` build, "
                "or feed nonces via `icopyzed crack --from-trace FILE`."
            )
            return []
        sector = block // 4
        logger.info("collect_encrypted_nonces: using %s", source.name)
        return source.collect(
            sector=sector,
            key_type=key_type,
            num=num_attempts,
            known_key=known_key,
        )


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
