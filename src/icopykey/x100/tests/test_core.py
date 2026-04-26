"""
Basic tests for x100_decrypt core components.

These tests exercise strategy detection, normalisation of raw and X100
dumps, and the high level engine.  They are intentionally simple and
should be expanded with additional vectors once real world sample dumps
are available.
"""

import struct
import tempfile
from pathlib import Path

import pytest  # type: ignore

from icopykey.x100.engine import DumpEngine
from icopykey.x100.strategies import get_strategy, RawFormatStrategy, X100FormatStrategy
from icopykey.x100.strategies import RawFormatStrategy as Raw
from icopykey.x100.strategies import X100FormatStrategy as X100


def test_raw_strategy_identification():
    # Create 64 bytes of raw data (4 blocks) – smaller than a full card
    raw_data = bytes([i % 256 for i in range(64)])
    strat = get_strategy(raw_data)
    assert isinstance(strat, RawFormatStrategy)


def test_x100_strategy_identification():
    # Build a minimal X100 dump: header + one 16 byte block
    header = struct.pack(">4sBBHI", b"X100", 1, 0, 12, 16)
    payload = b"\xAA" * 16
    dump = header + payload
    strat = get_strategy(dump)
    assert isinstance(strat, X100FormatStrategy)


def test_raw_normalisation_keys():
    # Create a 1K dump with known keys: each trailer block has distinct keys
    # We'll build 16 sectors (64 bytes each).  For each sector we fill the
    # last block (trailer) with key A = 0xA0A1A2A3A4A5 and key B = 0xB0B1B2B3B4B5
    data = bytearray()
    for sector in range(16):
        # three data blocks (fill with zeros)
        data.extend(b"\x00" * 16 * 3)
        # trailer block
        key_a = bytes([0xA0 + sector] * 6)
        access = b"\xff\x07\x80\x69"  # default access bits (transport config)
        key_b = bytes([0xB0 + sector] * 6)
        trailer = key_a + access + key_b
        data.extend(trailer)
    strat = Raw()
    dump = strat.normalize(bytes(data), strict=True)
    # There should be 16 key pairs
    assert len(dump.keys) == 16
    # Check first sector keys
    ka0, kb0 = dump.keys[0]
    assert ka0.startswith("a0") and kb0.startswith("b0")


def test_engine_processing(tmp_path: Path):
    # Write two small raw dumps to the temporary directory
    dump1 = b"\x00" * 64
    dump2 = b"\x11" * 64
    in_dir = tmp_path / "inputs"
    out_dir = tmp_path / "outputs"
    in_dir.mkdir()
    out_dir.mkdir()
    file1 = in_dir / "dump1.mfd"
    file2 = in_dir / "dump2.mfd"
    file1.write_bytes(dump1)
    file2.write_bytes(dump2)
    # Run engine
    engine = DumpEngine(use_external_recovery=False)
    engine.run(inputs=[str(in_dir)], output=str(out_dir), fmt="json", workers=1, strict=True)
    # Both output files should exist
    out_files = list(out_dir.iterdir())
    assert len(out_files) == 2
    # Check that JSON file contains base64 encoded data of correct length
    import json
    for f in out_files:
        with open(f, "r", encoding="utf-8") as fh:
            j = json.load(fh)
        # data base64 decode length should equal input size
        import base64
        decoded = base64.b64decode(j["data"])
        assert len(decoded) == 64