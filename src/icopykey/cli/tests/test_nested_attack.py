"""Tests for the nested-attack trace pipeline.

These tests exercise the trace-ingestion machinery and the structural
contract of :class:`NestedAttack`.  Algorithmic end-to-end recovery is
covered indirectly through the existing PRNG / keystream helpers — the
nested attack's value over the bare helpers is in the trace-loading and
validation glue rather than a new cryptographic primitive.

The JSON schema tested here is the contract for ``icopyzed crack
--from-trace`` and for the libnfc/nfcpy adapters in
:mod:`icopykey.cli.nfc_reader`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ..crypto1_attack import (
    NestedAttack,
    _ks32_for,
)


# ── from_trace_dict / from_trace_file ────────────────────────────────────


def test_from_trace_dict_minimal() -> None:
    payload = {
        "uid": "11223344",
        "target_sector": 4,
        "traces": [
            {"nt_enc": "aabbccdd"},
            {"nt_enc": "11223344"},
            {"nt_enc": "deadbeef"},
        ],
    }
    attack = NestedAttack.from_trace_dict(payload)
    assert attack._uid == bytes.fromhex("11223344")
    assert len(attack._encrypted_traces[4]) == 3


def test_from_trace_dict_with_known_key_and_nonce() -> None:
    payload = {
        "uid": "11223344",
        "target_sector": 4,
        "known_sector": 0,
        "known_key": "ffffffffffff",
        "known_nonce": "01020304",
        "traces": [
            {"nt_enc": "aabbccdd", "at_enc": "55667788", "nr": "ddeeff00", "distance": 160},
        ],
    }
    attack = NestedAttack.from_trace_dict(payload)
    assert attack._known_keys[0] == bytes.fromhex("ffffffffffff")
    assert attack._known_nonces[0] == 0x01020304
    nt_enc, at_enc, nr, dist = attack._encrypted_traces[4][0]
    assert nt_enc == bytes.fromhex("aabbccdd")
    assert at_enc == bytes.fromhex("55667788")
    assert nr == bytes.fromhex("ddeeff00")
    assert dist == 160


def test_from_trace_dict_missing_uid_raises() -> None:
    payload = {"target_sector": 1, "traces": []}
    with pytest.raises(ValueError, match="uid"):
        NestedAttack.from_trace_dict(payload)


def test_from_trace_file_round_trip(tmp_path: Path) -> None:
    payload = {
        "uid": "11223344",
        "target_sector": 7,
        "distance_window": [50, 280],
        "traces": [{"nt_enc": "aabbccdd"}],
    }
    p = tmp_path / "trace.json"
    p.write_text(json.dumps(payload))
    attack = NestedAttack.from_trace_file(p)
    assert attack._uid == bytes.fromhex("11223344")
    assert attack.DEFAULT_DISTANCE_WINDOW == (50, 280)
    assert len(attack._encrypted_traces[7]) == 1


# ── add_encrypted_trace validation ───────────────────────────────────────


def test_add_encrypted_trace_rejects_bad_lengths() -> None:
    attack = NestedAttack()
    attack.set_uid(b"\x11\x22\x33\x44")
    with pytest.raises(ValueError):
        attack.add_encrypted_trace(1, b"\x00\x00\x00")  # 3 bytes
    with pytest.raises(ValueError):
        attack.add_encrypted_trace(1, b"\x00" * 4, b"\x00\x00")  # bad at
    with pytest.raises(ValueError):
        attack.add_encrypted_trace(1, b"\x00" * 4, reader_nonce=b"\x00\x00\x00")


def test_add_encrypted_trace_back_compat_two_args() -> None:
    """Existing callers pass (sector, nt_enc, at_enc) positionally."""
    attack = NestedAttack()
    attack.set_uid(b"\x11\x22\x33\x44")
    attack.add_encrypted_trace(1, b"\x12\x34\x56\x78", b"\x9A\xBC\xDE\xF0")
    attack.add_encrypted_trace(1, b"\xDE\xAD\xBE\xEF", b"\xCA\xFE\xBA\xBE")
    assert len(attack._encrypted_traces[1]) == 2


def test_add_known_key_rejects_bad_length() -> None:
    attack = NestedAttack()
    with pytest.raises(ValueError):
        attack.add_known_key(0, b"\xFF" * 5)
    with pytest.raises(ValueError):
        attack.add_known_key(0, b"\xFF" * 7)


# ── recover_key behaviour ────────────────────────────────────────────────


def test_recover_key_no_traces_returns_none() -> None:
    attack = NestedAttack()
    attack.set_uid(b"\x11\x22\x33\x44")
    assert attack.recover_key(5) is None


def test_recover_key_path_a_invokes_prng_search() -> None:
    """3+ random nonces invoke the keystream/PRNG path.

    The random nonces almost certainly won't yield a real key (no
    structure), but the call must run to completion and either return a
    candidate or None — never raise.
    """
    attack = NestedAttack()
    attack.set_uid(b"\xDE\xAD\xBE\xEF")
    attack.add_encrypted_trace(2, b"\x12\x34\x56\x78")
    attack.add_encrypted_trace(2, b"\xDE\xAD\xBE\xEF")
    attack.add_encrypted_trace(2, b"\xCA\xFE\xBA\xBE")
    result = attack.recover_key(2)
    assert result is None or len(result) == 6


def test_recover_key_path_b_runs_with_known_nonce() -> None:
    """Path B (known key + known nonce) is invoked when registered.

    Random traces won't yield a real key, but we verify the path is
    exercised (no exceptions).
    """
    attack = NestedAttack()
    attack.set_uid(b"\xDE\xAD\xBE\xEF")
    attack.add_known_key(0, b"\xFF" * 6)
    attack.set_known_nonce(0, 0x12345678)
    attack.add_encrypted_trace(1, b"\xAA\xBB\xCC\xDD", distance_hint=160)
    # Narrow window so the test stays fast.
    result = attack.recover_key(1, distance_window=(140, 180))
    assert result is None or len(result) == 6


# ── self-consistent keystream / verify helpers ───────────────────────────


def test_ks32_for_is_deterministic() -> None:
    """_ks32_for must be stable for fixed inputs."""
    key = bytes.fromhex("a0a1a2a3a4a5")
    uid = bytes.fromhex("11223344")
    nt = 0xDEADBEEF
    ks_a = _ks32_for(key, uid, nt)
    ks_b = _ks32_for(key, uid, nt)
    assert ks_a == ks_b
    # Different nt → different keystream (with overwhelming probability).
    ks_c = _ks32_for(key, uid, 0xCAFEBABE)
    assert ks_a != ks_c


def test_ks32_for_varies_with_key_and_uid() -> None:
    """_ks32_for produces different keystreams for different keys/UIDs."""
    nt = 0xDEADBEEF
    ks_key1 = _ks32_for(bytes.fromhex("a0a1a2a3a4a5"), bytes.fromhex("11223344"), nt)
    ks_key2 = _ks32_for(bytes.fromhex("b0b1b2b3b4b5"), bytes.fromhex("11223344"), nt)
    ks_uid2 = _ks32_for(bytes.fromhex("a0a1a2a3a4a5"), bytes.fromhex("55667788"), nt)
    assert ks_key1 != ks_key2
    assert ks_key1 != ks_uid2


# ── cmd_crack_from_trace ─────────────────────────────────────────────────


def test_cmd_crack_from_trace_missing_file() -> None:
    from ..commands import cmd_crack_from_trace

    rc = cmd_crack_from_trace("/does/not/exist.json")
    assert rc == 2


def test_cmd_crack_from_trace_invalid_json(tmp_path: Path) -> None:
    from ..commands import cmd_crack_from_trace

    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    rc = cmd_crack_from_trace(str(bad))
    assert rc == 2


def test_cmd_crack_from_trace_runs_against_sample_fixture() -> None:
    """The bundled sample fixture loads and runs end-to-end.

    The synthetic nonces in the sample don't correspond to a real key,
    so we expect rc=1 (no key recovered), but the command must complete
    cleanly with no exceptions.
    """
    from ..commands import cmd_crack_from_trace

    repo_root = Path(__file__).resolve().parents[4]
    sample = repo_root / "tests" / "data" / "nested_traces" / "sample.json"
    assert sample.exists(), f"sample fixture missing at {sample}"
    rc = cmd_crack_from_trace(str(sample))
    assert rc in (0, 1)
