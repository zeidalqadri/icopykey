"""Canonical Crypto-1 cipher + key-recovery port.

Direct line-by-line port of the canonical reference implementation
shipped in :mod:`mfcuk` / :mod:`mfkey64`:

* https://github.com/nfc-tools/mfcuk/blob/master/src/crapto1.c
* https://github.com/Proxmark/proxmark3/blob/master/client/mifare/mfkey.c
* https://github.com/li0ard/crapto1/blob/master/crypto1/crapto1.c

This module exists because the in-house port in :mod:`crypto1_attack`
diverges from the canonical algorithm in several places (missing
odd/even role swap in :func:`crypto1_bit`, wrong key-loading convention,
interleaved ``oks``/``eks`` layout in :func:`lfsr_recovery64`), so it
cannot recover real MIFARE keys.  Rather than rewrite that module
in-place (which would break the many tests that depend on its current
behaviour), the canonical implementation is added here as a parallel
module.  New code should prefer these functions; the older module is
kept for the surface area it exposes to existing callers.

Reference: ``crapto1.c`` (C) 2008-2014 bla <blapost@gmail.com>, GPL v2.

Public surface
--------------

* :class:`Crypto1State` — 48-bit cipher state split into odd/even halves.
* :func:`crypto1_create` / :func:`crypto1_get_lfsr` — load key into
  state / extract key from state.
* :func:`crypto1_bit` / :func:`crypto1_byte` / :func:`crypto1_word` —
  forward keystream generation.
* :func:`lfsr_rollback_bit` / :func:`lfsr_rollback_byte` /
  :func:`lfsr_rollback_word` — exact inverses of the forward
  primitives.
* :func:`lfsr_recovery64` — recover candidate cipher states from 64
  bits of keystream (ks2 || ks3).
* :func:`prng_successor` — MIFARE PRNG.
* :func:`mfkey64` — recover the sector key given a full
  ``(uid, nt, nr, ar_enc, at_enc)`` auth trace, per the proxmark3
  reference.
"""

from __future__ import annotations

from dataclasses import dataclass

LF_POLY_ODD = 0x29CE5C
LF_POLY_EVEN = 0x870804


# ── bit / parity helpers ──────────────────────────────────────────────────


def _bit(x: int, n: int) -> int:
    """``BIT`` macro."""
    return (x >> n) & 1


def _bebit(x: int, n: int) -> int:
    """``BEBIT`` macro — bit ``n ^ 24`` of *x*."""
    return _bit(x, n ^ 24)


def _parity(x: int) -> int:
    """Even/odd parity of *x* (the canonical ``parity`` helper).

    Returns 0 if *x* has an even number of set bits, 1 otherwise.
    """
    x ^= x >> 16
    x ^= x >> 8
    x ^= x >> 4
    return (0x6996 >> (x & 0xF)) & 1


def _filter(x: int) -> int:
    """Canonical Crypto-1 filter function (5-nibble lookup)."""
    f = (0xF22C0 >> (x & 0xF)) & 16
    f |= (0x6C9C0 >> ((x >> 4) & 0xF)) & 8
    f |= (0x3C8B0 >> ((x >> 8) & 0xF)) & 4
    f |= (0x1E458 >> ((x >> 12) & 0xF)) & 2
    f |= (0x0D938 >> ((x >> 16) & 0xF)) & 1
    return _bit(0xEC57E80A, f)


# ── State ────────────────────────────────────────────────────────────────


@dataclass
class Crypto1State:
    """48-bit Crypto-1 LFSR state split into two 24-bit halves.

    The cipher alternates which half feeds the filter every clock; the
    canonical implementation models that with an explicit swap inside
    :func:`crypto1_bit` and :func:`lfsr_rollback_bit`, so ``odd`` and
    ``even`` here are *not* permanently bound to specific bits of the
    underlying 48-bit state — they swap roles each clock.
    """

    odd: int = 0
    even: int = 0

    def copy(self) -> Crypto1State:
        return Crypto1State(self.odd, self.even)


# ── Forward cipher ───────────────────────────────────────────────────────


def crypto1_create(key: int) -> Crypto1State:
    """Load a 48-bit key into a fresh cipher state.

    Mirrors the canonical loop:

    .. code:: c

       for(i = 47; i > 0; i -= 2) {
           s->odd  = s->odd  << 1 | BIT(key, (i - 1) ^ 7);
           s->even = s->even << 1 | BIT(key, i ^ 7);
       }
    """
    s = Crypto1State()
    i = 47
    while i > 0:
        s.odd = ((s.odd << 1) | _bit(key, (i - 1) ^ 7)) & 0xFFFFFF
        s.even = ((s.even << 1) | _bit(key, i ^ 7)) & 0xFFFFFF
        i -= 2
    return s


def crypto1_get_lfsr(s: Crypto1State) -> int:
    """Reverse of :func:`crypto1_create`: extract the 48-bit key."""
    lfsr = 0
    for i in range(23, -1, -1):
        lfsr = (lfsr << 1) | _bit(s.odd, i ^ 3)
        lfsr = (lfsr << 1) | _bit(s.even, i ^ 3)
    return lfsr & 0xFFFFFFFFFFFF


def crypto1_bit(s: Crypto1State, in_bit: int, is_encrypted: int) -> int:
    """Clock the cipher once, return one keystream bit.

    Direct port of the canonical:

    .. code:: c

       uint8_t crypto1_bit(struct Crypto1State *s, uint8_t in, int is_encrypted) {
           uint32_t feedin;
           uint8_t ret = filter(s->odd);
           feedin  = ret & !!is_encrypted;
           feedin ^= !!in;
           feedin ^= LF_POLY_ODD & s->odd;
           feedin ^= LF_POLY_EVEN & s->even;
           s->even = s->even << 1 | parity(feedin);
           s->odd ^= (s->odd ^= s->even, s->even ^= s->odd);  // swap
           return ret;
       }
    """
    ret = _filter(s.odd)
    feedin = ret & (1 if is_encrypted else 0)
    feedin ^= 1 if in_bit else 0
    feedin ^= LF_POLY_ODD & s.odd
    feedin ^= LF_POLY_EVEN & s.even
    s.even = ((s.even << 1) | _parity(feedin)) & 0xFFFFFF
    s.odd, s.even = s.even, s.odd  # canonical XOR-swap idiom
    return ret


def crypto1_byte(s: Crypto1State, in_byte: int, is_encrypted: int) -> int:
    ret = 0
    for i in range(8):
        ret |= crypto1_bit(s, _bit(in_byte, i), is_encrypted) << i
    return ret


def crypto1_word(s: Crypto1State, in_word: int, is_encrypted: int) -> int:
    ret = 0
    for i in range(32):
        ret |= crypto1_bit(s, _bebit(in_word, i), is_encrypted) << (i ^ 24)
    return ret


# ── Rollback (exact inverses) ────────────────────────────────────────────


def lfsr_rollback_bit(s: Crypto1State, in_bit: int, fb: int) -> int:
    """Roll back one clock; return the filter output that the forward
    clock would have emitted.  Exact inverse of :func:`crypto1_bit`.

    .. code:: c

       uint8_t lfsr_rollback_bit(struct Crypto1State *s, uint32_t in, int fb) {
           int out;
           uint8_t ret;
           uint32_t t;

           s->odd &= 0xffffff;
           t = s->odd, s->odd = s->even, s->even = t;

           out  = s->even & 1;
           out ^= LF_POLY_EVEN & (s->even >>= 1);
           out ^= LF_POLY_ODD & s->odd;
           out ^= !!in;
           out ^= (ret = filter(s->odd)) & !!fb;

           s->even |= parity(out) << 23;
           return ret;
       }
    """
    s.odd &= 0xFFFFFF
    s.odd, s.even = s.even, s.odd  # swap

    out = s.even & 1
    s.even >>= 1
    out ^= LF_POLY_EVEN & s.even
    out ^= LF_POLY_ODD & s.odd
    out ^= 1 if in_bit else 0
    ret = _filter(s.odd)
    out ^= ret & (1 if fb else 0)

    s.even |= _parity(out) << 23
    s.even &= 0xFFFFFF
    return ret


def lfsr_rollback_byte(s: Crypto1State, in_byte: int, fb: int) -> int:
    ret = 0
    for i in range(7, -1, -1):
        ret |= lfsr_rollback_bit(s, _bit(in_byte, i), fb) << i
    return ret


def lfsr_rollback_word(s: Crypto1State, in_word: int, fb: int) -> int:
    ret = 0
    for i in range(31, -1, -1):
        ret |= lfsr_rollback_bit(s, _bebit(in_word, i), fb) << (i ^ 24)
    return ret


# ── PRNG ─────────────────────────────────────────────────────────────────


def prng_successor(x: int, n: int) -> int:
    """MIFARE PRNG: return the nonce *n* steps after *x*."""
    for _ in range(n):
        x = (x >> 1) | (((x ^ (x >> 2) ^ (x >> 3) ^ (x >> 5)) << 15) & 0xFFFF)
        x &= 0xFFFF
    return x


# ── lfsr_recovery64 ──────────────────────────────────────────────────────

_S1 = [
    0x62141, 0x310A0, 0x18850, 0x0C428, 0x06214, 0x0310A, 0x85E30, 0xC69AD,
    0x634D6, 0xB5CDE, 0xDE8DA, 0x6F46D, 0xB3C83, 0x59E41, 0xA8995, 0xD027F,
    0x6813F, 0x3409F, 0x9E6FA,
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


def _extend_table_simple(table: list[int], bit: int) -> list[int]:
    """Port of canonical ``extend_table_simple``.

    The canonical implementation uses ``uint32_t`` storage and lets
    values grow into the full 32-bit window — the high bits accumulate
    information used later by the C1/C2/S2/T2 parity checks.  Do **not**
    mask to 24 bits.
    """
    out: list[int] = []
    for v in table:
        v = (v << 1) & 0xFFFFFFFF
        f0 = _filter(v)
        f1 = _filter(v | 1)
        if f0 != f1:
            out.append(v | (f0 ^ bit))
        elif f0 == bit:
            out.append(v)
            out.append(v | 1)
        # else: drop
    return out


def lfsr_recovery64(ks2: int, ks3: int) -> list[Crypto1State]:
    """Recover candidate cipher states from 64 keystream bits.

    Port of canonical ``lfsr_recovery64`` — note ``oks``/``eks`` are
    *concatenated* (ks2 first 16, ks3 next 16), **not** interleaved.
    """
    oks = [0] * 32
    eks = [0] * 32
    for i in range(30, -1, -2):
        oks[i >> 1] = _bebit(ks2, i)
        oks[16 + (i >> 1)] = _bebit(ks3, i)
    for i in range(31, -1, -2):
        eks[i >> 1] = _bebit(ks2, i)
        eks[16 + (i >> 1)] = _bebit(ks3, i)

    statelist: list[Crypto1State] = []

    for i in range(0xFFFFF, -1, -1):
        if _filter(i) != oks[0]:
            continue

        table = [i]
        for j in range(1, 29):
            table = _extend_table_simple(table, oks[j])
            if not table:
                break
        if not table:
            continue

        low = 0
        for j in range(19):
            low = (low << 1) | _parity(i & _S1[j])
        hi = [0] * 32
        for j in range(32):
            hi[j] = _parity(i & _T1[j])

        for tail_val in table:
            cont2 = False
            for j in range(3):
                tail_val = (tail_val << 1) & 0xFFFFFFFF
                tail_val |= _parity((i & _C1[j]) ^ (tail_val & _C2[j]))
                if _filter(tail_val) != oks[29 + j]:
                    cont2 = True
                    break
            if cont2:
                continue

            win = 0
            for j in range(19):
                win = (win << 1) | _parity(tail_val & _S2[j])
            win ^= low

            for j in range(32):
                win = ((win << 1) ^ hi[j] ^ _parity(tail_val & _T2[j])) & 0xFFFFFFFF
                if _filter(win) != eks[j]:
                    cont2 = True
                    break
            if cont2:
                continue

            tail_val = ((tail_val << 1) | _parity(LF_POLY_EVEN & tail_val)) & 0xFFFFFFFF
            sl = Crypto1State(
                odd=(tail_val ^ _parity(LF_POLY_ODD & win)) & 0xFFFFFF,
                even=win & 0xFFFFFF,
            )
            statelist.append(sl)

    return statelist


# ── mfkey64 ──────────────────────────────────────────────────────────────


def mfkey64(uid: int, nt: int, nr: int, ar_enc: int, at_enc: int) -> int | None:
    """Recover the sector key from one complete MIFARE auth trace.

    Port of the canonical proxmark3 ``mfkey64`` algorithm.

    Parameters
    ----------
    uid : int (32-bit)
        Card UID.
    nt : int (32-bit)
        Plaintext tag challenge.
    nr : int (32-bit)
        Plaintext reader challenge.
    ar_enc : int (32-bit)
        Encrypted reader response (= ``prng_successor(nt, 64) XOR ks2``).
    at_enc : int (32-bit)
        Encrypted tag response (= ``prng_successor(nt, 96) XOR ks3``).

    Returns
    -------
    int | None
        The recovered 48-bit key, or ``None`` if recovery failed.
    """
    ks2 = ar_enc ^ prng_successor(nt, 64)
    ks3 = at_enc ^ prng_successor(nt, 96)

    states = lfsr_recovery64(ks2, ks3)
    if not states:
        return None

    revstate = states[0]
    lfsr_rollback_word(revstate, 0, 0)
    lfsr_rollback_word(revstate, 0, 0)
    lfsr_rollback_word(revstate, nr, 1)
    lfsr_rollback_word(revstate, uid ^ nt, 0)
    return crypto1_get_lfsr(revstate)


def mfkey64_bytes(
    uid: bytes, nt: bytes, nr: bytes, ar_enc: bytes, at_enc: bytes
) -> bytes | None:
    """Convenience wrapper accepting big-endian byte strings.

    All inputs are 4 bytes except the return, which is 6 bytes (the
    48-bit MIFARE Classic key) or None.
    """
    key = mfkey64(
        int.from_bytes(uid, "big"),
        int.from_bytes(nt, "big"),
        int.from_bytes(nr, "big"),
        int.from_bytes(ar_enc, "big"),
        int.from_bytes(at_enc, "big"),
    )
    if key is None:
        return None
    return key.to_bytes(6, "big")
