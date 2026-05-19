"""End-to-end key recovery tests against synthetic ground-truth nonces.

These tests do what the existing test_crypto1_attack.py / test_nested_attack.py
suites do NOT: they assert that a recovered key actually equals the target
key used to generate the trace.  The trace is built by running the real
Crypto-1 cipher forward; if recovery doesn't agree with the cipher we
have a bug in the recovery code.

**Current status (2026-05-19): the round-trip test is xfail.**

Diagnosis:
    * :func:`lfsr_rollback_word` cannot exactly invert
      :func:`crypto1_word` for a full 32-bit cycle — confirmed by the
      already-xfail'd ``test_lfsr_rollback_word`` and reproduced here.
    * The cipher init sequence runs 64 LFSR clocks (32 UID + 32 NT),
      which is more than the rollback can recover (the odd register is
      24 bits wide).
    * :func:`lfsr_recovery32` returns ~65k candidate states; empirical
      probing shows none of them match the actual cipher state at
      either "after UID feed" or "after UID+NT feed."
    * The pre-existing tests for ``recover_key_from_keystream`` only
      check that the function returns a list, not that the list
      contains the correct key.

To make this pass, port the linear LFSR-inversion code from
``crapto1.c`` (``lfsr_recovery_state_from_keystream`` plus parity
correlation tables).  Until then, real key recovery should go through
``mfcuk`` via :class:`icopykey.cli.nfc_reader.LibNfcCLINonceSource`.
"""

from __future__ import annotations

import pytest

from ..crypto1_attack import (
    _ks32_for,
    recover_key_from_keystream,
)


# A handful of (target_key, uid, nt) triples covering different key
# layouts and a range of nt PRNG values.
ROUND_TRIP_CASES = [
    pytest.param(
        bytes.fromhex("a0a1a2a3a4a5"),
        bytes.fromhex("11223344"),
        0xDEADBEEF,
        id="key-a0a1...-uid-1122-nt-deadbeef",
    ),
    pytest.param(
        bytes.fromhex("ffffffffffff"),
        bytes.fromhex("01020304"),
        0x12345678,
        id="key-ff...-uid-0102-nt-12345678",
    ),
    pytest.param(
        bytes.fromhex("b0b1b2b3b4b5"),
        bytes.fromhex("55667788"),
        0xCAFEBABE,
        id="key-b0b1...-uid-5566-nt-cafebabe",
    ),
]


@pytest.mark.xfail(
    reason=(
        "recover_key_from_keystream cannot recover real keys without the "
        "linear LFSR-inversion machinery from crapto1.c. lfsr_rollback_word "
        "loses bits on full 32-bit cycles and lfsr_recovery32 returns ~65k "
        "false-positive candidates. See module docstring for details."
    ),
    strict=True,
)
@pytest.mark.parametrize("target_key, uid, nt", ROUND_TRIP_CASES)
def test_recover_key_from_keystream_round_trip(
    target_key: bytes, uid: bytes, nt: int
) -> None:
    """Encrypt nt with target_key+uid, recover, assert target_key is found.

    ``_ks32_for`` replicates the cipher init sequence (key → feed UID →
    feed NT) and returns the 32 keystream bits emitted while the NT
    bits are fed — exactly what encrypts ``{nt}`` on the wire.  Hand
    that keystream + plaintext nt to ``recover_key_from_keystream`` and
    check the original key comes back in the candidate list.

    Marked xfail strict=True so this test becomes a green-light when
    the underlying algorithm is fixed.
    """
    ks = _ks32_for(target_key, uid, nt)
    candidates = recover_key_from_keystream(ks, uid, nt)
    assert isinstance(candidates, list)
    assert target_key in candidates, (
        f"target_key {target_key.hex()} not recovered. "
        f"Got {len(candidates)} candidates: "
        f"{[c.hex() for c in candidates[:5]]}"
        + ("..." if len(candidates) > 5 else "")
    )
