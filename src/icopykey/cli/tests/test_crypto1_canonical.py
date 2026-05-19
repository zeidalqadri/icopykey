"""Round-trip tests for the canonical crypto1 port.

These tests build a synthetic MIFARE auth trace by running the cipher
forward (with the canonical convention from crapto1.c) and then call
mfkey64 on the trace to recover the key.  Recovery must yield the
target key on every case.

If any of these fail, the algorithm port has regressed — fix the port,
not the test.
"""

from __future__ import annotations

import random

import pytest

from ..crypto1_canonical import (
    Crypto1State,
    crypto1_create,
    crypto1_get_lfsr,
    crypto1_word,
    lfsr_rollback_word,
    mfkey64,
    mfkey64_bytes,
    prng_successor,
)


# ── Cipher load/get round-trip ───────────────────────────────────────────


@pytest.mark.parametrize(
    "key",
    [
        0xFFFFFFFFFFFF,
        0x000000000000,
        0xA0A1A2A3A4A5,
        0xB0B1B2B3B4B5,
        0x4D3A99C351DD,
        0xD3F7D3F7D3F7,
    ],
)
def test_crypto1_create_then_get_lfsr_round_trip(key: int) -> None:
    """crypto1_get_lfsr(crypto1_create(k)) == k."""
    s = crypto1_create(key)
    assert crypto1_get_lfsr(s) == key


# ── Forward + rollback round-trip (cipher primitives) ────────────────────


def test_crypto1_word_lfsr_rollback_word_round_trip() -> None:
    """A forward crypto1_word followed by lfsr_rollback_word restores state."""
    s = crypto1_create(0xA0A1A2A3A4A5)
    snapshot = Crypto1State(s.odd, s.even)
    crypto1_word(s, 0x12345678, 0)
    lfsr_rollback_word(s, 0x12345678, 0)
    assert s.odd == snapshot.odd and s.even == snapshot.even


def test_crypto1_word_lfsr_rollback_word_round_trip_fb1() -> None:
    """Same, but with fb=1 (the NR phase of MIFARE auth)."""
    s = crypto1_create(0xFFFFFFFFFFFF)
    snapshot = Crypto1State(s.odd, s.even)
    crypto1_word(s, 0xDEADBEEF, 1)
    lfsr_rollback_word(s, 0xDEADBEEF, 1)
    assert s.odd == snapshot.odd and s.even == snapshot.even


# ── mfkey64 recovery round-trip ──────────────────────────────────────────


HANDPICKED_CASES = [
    # (key, uid, nt, nr)
    (0xFFFFFFFFFFFF, 0x11223344, 0xDEADBEEF, 0x11223344),
    (0xA0A1A2A3A4A5, 0x11223344, 0xDEADBEEF, 0xCAFEBABE),
    (0xB0B1B2B3B4B5, 0x55667788, 0xCAFEBABE, 0x12345678),
    (0x4D3A99C351DD, 0x01020304, 0x12345678, 0xABCDEF01),
    (0x000000000000, 0xFFFFFFFF, 0x00000001, 0xFEDCBA98),
]


def _build_trace(
    key: int, uid: int, nt: int, nr: int
) -> tuple[int, int]:
    """Forward-encrypt one MIFARE auth and return (ar_enc, at_enc).

    Models the canonical auth sequence:
      * init: feed (uid XOR nt) for 32 clocks (block 1, ks_init encrypts {nt})
      * block 2: feed nr with fb=1 (ks_b2 encrypts {nr})
      * block 3: feed zeros, ks2 encrypts ar (= suc(nt, 64))
      * block 4: feed zeros, ks3 encrypts at (= suc(nt, 96))
    """
    state = crypto1_create(key)
    crypto1_word(state, uid ^ nt, 0)
    crypto1_word(state, nr, 1)
    ks2 = crypto1_word(state, 0, 0)
    ks3 = crypto1_word(state, 0, 0)
    ar_enc = prng_successor(nt, 64) ^ ks2
    at_enc = prng_successor(nt, 96) ^ ks3
    return ar_enc, at_enc


@pytest.mark.parametrize("key, uid, nt, nr", HANDPICKED_CASES)
def test_mfkey64_recovers_handpicked_keys(
    key: int, uid: int, nt: int, nr: int
) -> None:
    """End-to-end: forward-build a trace, feed to mfkey64, recover the key."""
    ar_enc, at_enc = _build_trace(key, uid, nt, nr)
    recovered = mfkey64(uid, nt, nr, ar_enc, at_enc)
    assert recovered == key, (
        f"target={key:012x} recovered={recovered:012x if recovered is not None else 'None'}"
    )


@pytest.mark.slow
def test_mfkey64_recovers_random_keys() -> None:
    """Stress test: 10 random (key, uid, nt, nr) tuples; all must recover.

    Marked @slow because each call iterates ~2^20 candidates in pure
    Python (~2 s/case).  Disable with `pytest -m 'not slow'`.
    """
    rng = random.Random(42)
    for _ in range(10):
        key = rng.getrandbits(48)
        uid = rng.getrandbits(32)
        nt = rng.getrandbits(32)
        nr = rng.getrandbits(32)
        ar_enc, at_enc = _build_trace(key, uid, nt, nr)
        recovered = mfkey64(uid, nt, nr, ar_enc, at_enc)
        assert recovered == key, (
            f"FAILED: target={key:012x} uid={uid:08x} nt={nt:08x} nr={nr:08x} "
            f"recovered={recovered:012x if recovered is not None else 'None'}"
        )


# ── mfkey64_bytes wrapper ────────────────────────────────────────────────


def test_mfkey64_bytes_wrapper_round_trip() -> None:
    """The bytes-input wrapper matches the int-input version."""
    key = 0xA0A1A2A3A4A5
    uid = 0x11223344
    nt = 0xDEADBEEF
    nr = 0xCAFEBABE
    ar_enc, at_enc = _build_trace(key, uid, nt, nr)
    recovered = mfkey64_bytes(
        uid.to_bytes(4, "big"),
        nt.to_bytes(4, "big"),
        nr.to_bytes(4, "big"),
        ar_enc.to_bytes(4, "big"),
        at_enc.to_bytes(4, "big"),
    )
    assert recovered == key.to_bytes(6, "big")
