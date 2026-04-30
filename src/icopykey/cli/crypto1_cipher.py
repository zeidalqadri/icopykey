"""MIFARE Classic Crypto-1 stream cipher and access conditions.

Uses the correct split 24-bit LFSR primitives from ``crypto1_attack.py``
(port of crapto1.c by Roel Verdult / libnfc community) rather than
the previous single 48-bit LFSR with a wrong polynomial.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

from .crypto1_attack import (
    Crypto1State,
    crypto1_bit,
    crypto1_byte,
    crypto1_word,
    lfsr_rollback_bit,
    lfsr_rollback_word,
    _filter as _filter_20bit,
    recover_key as _recover_key,
    DarksideAttack,
)


class AccessCondition(enum.Enum):
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


class Crypto1:
    """MIFARE Classic Crypto-1 stream cipher using the split 24×2 LFSR.

    The LFSR state is split into *odd* and *even* 24-bit halves based on
    the alternating feedback structure of the Crypto-1 cipher.
    Keystream generation and key recovery delegate to the primitive
    functions in ``crypto1_attack.py``.

    References:
        - libnfc / mfoc: https://github.com/nfc-tools/mfoc
        - Garcia et al., "Wirelessly Pickpocketing a Mifare Classic Card"
          (IEEE S&P 2009)
        - crapto1.c by Roel Verdult, bla, and the libnfc community
    """

    def __init__(self) -> None:
        self.state: Crypto1State = Crypto1State()
        self._uid: bytes | None = None
        self._nt: int | None = None

    # ── Key loading ─────────────────────────────────────────────

    def init(self, key: bytes) -> None:
        """Load a 6-byte key into the LFSR state.

        The key occupies all 48 bits:
            even = key[0:3] (MSB), odd = key[3:6] (LSB)
        """
        if len(key) != 6:
            raise ValueError("Key must be 6 bytes")
        full = int.from_bytes(key, "big")
        self.state = Crypto1State(
            odd=full & 0xFFFFFF,
            even=(full >> 24) & 0xFFFFFF,
        )

    def init_with_tag(self, key: bytes, uid: bytes, nt: bytes) -> None:
        """Initialise LFSR with key, card UID, and tag nonce.

        Implements the real Crypto-1 init sequence:
            1. Load key into state
            2. Feed 32 bits of UID (LSB first) through LFSR
            3. Feed 32 bits of NT  (LSB first) through LFSR
        """
        self.init(key)
        self._uid = uid
        nt_int = int.from_bytes(nt, "little") & 0xFFFFFFFF
        self._nt = nt_int
        uid_int = int.from_bytes(uid, "little") & 0xFFFFFFFF

        for i in range(32):
            crypto1_bit(self.state, (uid_int >> i) & 1, 0)
        for i in range(32):
            crypto1_bit(self.state, (nt_int >> i) & 1, 0)

    # ── Keystream generation ────────────────────────────────────

    def generate_keystream(self, length: int) -> bytes:
        """Generate ``length`` bytes of Crypto-1 keystream."""
        ks = bytearray()
        for _ in range(length):
            ks.append(crypto1_byte(self.state, 0, 0))
        return bytes(ks)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with keystream (XOR — symmetric)."""
        ks = self.generate_keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data (same operation as encrypt)."""
        return self.encrypt(data)

    # ── 3-pass authentication ───────────────────────────────────

    def authenticate(
        self, uid: bytes, block: int, key: bytes
    ) -> tuple[bytes | None, bytes | None]:
        """Perform 3-pass authentication for a given block.

        Returns
        -------
        tuple
            (nr, ar) — reader nonce and tag response, or (None, None).
        """
        nt = int.from_bytes(uid[:4], "little") ^ block
        self.init_with_tag(key, uid, nt.to_bytes(4, "little"))
        nr = self.generate_keystream(4)
        response = self.generate_keystream(4)
        return (nr, response)

    # ── Key recovery ────────────────────────────────────────────

    @staticmethod
    def crack_key(
        nonce: bytes,
        response: bytes,
        uid: bytes,
        tag_nonce: int = 0,
        nr: int = 0,
        ar: int = 0,
    ) -> bytes | None:
        """Recover a MIFARE Classic key from authentication data.

        Parameters
        ----------
        nonce : bytes
            Keystream recovered from the encrypted tag nonce.
        response : bytes
            Keystream recovered from the encrypted reader response.
        uid : bytes
            Card UID (4 bytes, little-endian).
        tag_nonce : int
            Plaintext tag nonce {nt} (optional for full recovery).
        nr : int
            Reader nonce (optional).
        ar : int
            Tag response {ar} (optional).

        Returns
        -------
        bytes | None
            6-byte key or None if recovery fails.
        """
        if tag_nonce and nr and ar:
            return _recover_key(nonce, uid, tag_nonce, nr, ar)
        return None
