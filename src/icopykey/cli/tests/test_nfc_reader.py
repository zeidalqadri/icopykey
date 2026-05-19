"""Tests for the external NFC reader interface."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from icopykey.cli.nfc_reader import (
    KeyRecoverySource,
    LibNfcCLIKeyRecovery,
    LibNfcCLINonceSource,
    NfcReader,
    NfcpyNonceSource,
    NonceSource,
    PcscReader,
    auto_key_recovery_source,
    auto_nonce_source,
    create_reader,
)


def test_pcsc_reader_available():
    """PcscReader.available should return False if pyscard not installed."""
    reader = PcscReader()
    # May be True or False depending on environment
    assert isinstance(reader.available, bool)


def test_pcsc_reader_not_connected():
    """PcscReader methods work without connection."""
    reader = PcscReader()
    assert not reader.is_connected()
    assert reader.get_card_uid() is None
    assert not reader.authenticate(0, b"\xFF" * 6)
    assert reader.read_block(0) is None


def test_pcsc_reader_disconnect_noop():
    """Disconnecting without connect does not crash."""
    reader = PcscReader()
    reader.disconnect()
    assert not reader.is_connected()


def test_create_reader_auto():
    """create_reader returns a reader instance or None."""
    reader = create_reader("auto")
    assert reader is None or isinstance(reader, NfcReader)


def test_create_reader_pcsc():
    """create_reader('pcsc') returns a PcscReader."""
    reader = create_reader("pcsc")
    assert isinstance(reader, PcscReader)


def test_create_reader_unknown():
    """create_reader with unknown kind returns None."""
    reader = create_reader("unknown")
    assert reader is None


def test_abstract_instantiation():
    """NfcReader cannot be instantiated directly (ABC)."""
    with pytest.raises(TypeError):
        NfcReader()  # type: ignore


# ── NonceSource backends ──────────────────────────────────────────────────


def test_nonce_source_abstract() -> None:
    """NonceSource cannot be instantiated directly."""
    with pytest.raises(TypeError):
        NonceSource()  # type: ignore[abstract]


def test_libnfc_nonce_source_available_uses_path() -> None:
    """LibNfcCLINonceSource.available follows shutil.which('mfcuk')."""
    src = LibNfcCLINonceSource()
    with patch("icopykey.cli.nfc_reader.shutil.which", return_value=None):
        assert src.available is False
    with patch("icopykey.cli.nfc_reader.shutil.which", return_value="/usr/bin/mfcuk"):
        assert src.available is True


def test_libnfc_collect_returns_empty_when_unavailable() -> None:
    src = LibNfcCLINonceSource()
    with patch("icopykey.cli.nfc_reader.shutil.which", return_value=None):
        nonces = src.collect(sector=4)
    assert nonces == []


def test_libnfc_collect_parses_stdout() -> None:
    """Stdout containing Nt = 0xXXXXXXXX lines yields parsed nonces."""
    src = LibNfcCLINonceSource()
    fake_stdout = "Nt = 0x11223344\nignored\nNt = 0xdeadbeef and trailing\nNt = 0xCAFEBABE"
    fake_proc = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=fake_stdout, stderr=""
    )
    with patch.object(LibNfcCLINonceSource, "available", new=True), patch(
        "icopykey.cli.nfc_reader.subprocess.run", return_value=fake_proc
    ):
        nonces = src.collect(sector=4, num=10)
    assert nonces == [
        bytes.fromhex("11223344"),
        bytes.fromhex("deadbeef"),
        bytes.fromhex("cafebabe"),
    ]


def test_libnfc_collect_handles_timeout() -> None:
    """A subprocess timeout returns [] (does not raise)."""
    src = LibNfcCLINonceSource()
    with patch.object(LibNfcCLINonceSource, "available", new=True), patch(
        "icopykey.cli.nfc_reader.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="mfcuk", timeout=1),
    ):
        nonces = src.collect(sector=4)
    assert nonces == []


def test_nfcpy_source_available_when_nfc_imported() -> None:
    """NfcpyNonceSource.available reflects whether `nfc` imports."""
    src = NfcpyNonceSource()
    # Just confirm the boolean type; actual availability depends on env.
    assert isinstance(src.available, bool)


def test_auto_nonce_source_returns_none_when_none_installed() -> None:
    """auto_nonce_source returns None when no backend is available."""

    class FakeUnavailable(NonceSource):
        name = "fake"

        @property
        def available(self) -> bool:
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
            return []

    with patch(
        "icopykey.cli.nfc_reader._NONCE_SOURCE_CLASSES",
        (FakeUnavailable,),
    ):
        assert auto_nonce_source() is None


def test_pcsc_collect_nonces_delegates_to_auto_source() -> None:
    """PcscReader.collect_encrypted_nonces routes through auto_nonce_source."""

    captured: dict[str, int | bytes | None] = {}

    class FakeSource(NonceSource):
        name = "fake"

        @property
        def available(self) -> bool:
            return True

        def collect(
            self,
            sector: int,
            *,
            key_type: int = 0x60,
            num: int = 256,
            known_key: bytes | None = None,
            timeout: float = 120.0,
        ) -> list[bytes]:
            captured["sector"] = sector
            captured["num"] = num
            captured["known_key"] = known_key
            return [b"\x12\x34\x56\x78", b"\x9a\xbc\xde\xf0"]

    reader = PcscReader()
    with patch(
        "icopykey.cli.nfc_reader.auto_nonce_source", return_value=FakeSource()
    ):
        nonces = reader.collect_encrypted_nonces(
            block=20, num_attempts=64, known_key=b"\xff" * 6
        )
    assert nonces == [b"\x12\x34\x56\x78", b"\x9a\xbc\xde\xf0"]
    assert captured == {"sector": 5, "num": 64, "known_key": b"\xff" * 6}


# ── KeyRecoverySource backends (mfcuk -R) ────────────────────────────────


def test_key_recovery_source_abstract() -> None:
    """KeyRecoverySource cannot be instantiated directly."""
    with pytest.raises(TypeError):
        KeyRecoverySource()  # type: ignore[abstract]


def test_libnfc_recovery_available_uses_path() -> None:
    src = LibNfcCLIKeyRecovery()
    with patch("icopykey.cli.nfc_reader.shutil.which", return_value=None):
        assert src.available is False
    with patch("icopykey.cli.nfc_reader.shutil.which", return_value="/usr/bin/mfcuk"):
        assert src.available is True


def test_libnfc_recovery_returns_none_when_unavailable() -> None:
    src = LibNfcCLIKeyRecovery()
    with patch("icopykey.cli.nfc_reader.shutil.which", return_value=None):
        assert src.recover_sector(sector=4) is None


def test_libnfc_recovery_parses_canonical_output() -> None:
    """mfcuk's INFO: block N recovered KEY: <hex> line is parsed."""
    src = LibNfcCLIKeyRecovery()
    fake_stdout = (
        "[*] Setting up nfc reader...\n"
        "[*] Probing tag for block 16:A ...\n"
        "INFO: block 16 recovered KEY: a0a1a2a3a4a5\n"
        "[*] Done.\n"
    )
    fake_proc = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=fake_stdout, stderr=""
    )
    with (
        patch.object(LibNfcCLIKeyRecovery, "available", new=True),
        patch("icopykey.cli.nfc_reader.subprocess.run", return_value=fake_proc),
    ):
        key = src.recover_sector(sector=4)
    assert key == bytes.fromhex("a0a1a2a3a4a5")


def test_libnfc_recovery_returns_none_on_no_key_line() -> None:
    """Output without the canonical INFO line yields None, not a crash."""
    src = LibNfcCLIKeyRecovery()
    fake_proc = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="some unrelated output\n", stderr="failure"
    )
    with (
        patch.object(LibNfcCLIKeyRecovery, "available", new=True),
        patch("icopykey.cli.nfc_reader.subprocess.run", return_value=fake_proc),
    ):
        key = src.recover_sector(sector=4)
    assert key is None


def test_libnfc_recovery_passes_known_keys_as_d_flags() -> None:
    """Known keys should be forwarded as repeated -d <hex> arguments."""
    src = LibNfcCLIKeyRecovery()
    fake_stdout = "INFO: block 0 recovered KEY: ffffffffffff\n"
    fake_proc = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=fake_stdout, stderr=""
    )
    captured_cmd: dict[str, list[str]] = {}

    def fake_run(cmd, **_kwargs):
        captured_cmd["cmd"] = cmd
        return fake_proc

    with (
        patch.object(LibNfcCLIKeyRecovery, "available", new=True),
        patch("icopykey.cli.nfc_reader.subprocess.run", side_effect=fake_run),
    ):
        key = src.recover_sector(
            sector=0,
            known_keys=[bytes.fromhex("a0a1a2a3a4a5"), bytes.fromhex("b0b1b2b3b4b5")],
        )
    assert key == bytes.fromhex("ffffffffffff")
    cmd = captured_cmd["cmd"]
    # -d KEY pairs for each known key, plus -R 0:A
    assert "-R" in cmd and "0:A" in cmd
    d_indices = [i for i, a in enumerate(cmd) if a == "-d"]
    assert len(d_indices) == 2
    assert cmd[d_indices[0] + 1] == "A0A1A2A3A4A5"
    assert cmd[d_indices[1] + 1] == "B0B1B2B3B4B5"


def test_libnfc_recovery_handles_timeout() -> None:
    src = LibNfcCLIKeyRecovery()
    with (
        patch.object(LibNfcCLIKeyRecovery, "available", new=True),
        patch(
            "icopykey.cli.nfc_reader.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="mfcuk", timeout=1),
        ),
    ):
        assert src.recover_sector(sector=4) is None


def test_auto_key_recovery_source_picks_available() -> None:
    """auto_key_recovery_source returns the first available backend."""

    class FakeAvailable(KeyRecoverySource):
        name = "fake"

        @property
        def available(self) -> bool:
            return True

        def recover_sector(
            self,
            sector: int,
            *,
            key_type: int = 0x60,
            known_keys: list[bytes] | None = None,
            timeout: float = 600.0,
        ) -> bytes | None:
            return bytes.fromhex("ffffffffffff")

    with patch("icopykey.cli.nfc_reader._KEY_RECOVERY_CLASSES", (FakeAvailable,)):
        src = auto_key_recovery_source()
    assert src is not None
    assert src.recover_sector(4) == bytes.fromhex("ffffffffffff")


def test_auto_key_recovery_source_none_when_unavailable() -> None:
    class FakeUnavailable(KeyRecoverySource):
        name = "fake"

        @property
        def available(self) -> bool:
            return False

        def recover_sector(
            self,
            sector: int,
            *,
            key_type: int = 0x60,
            known_keys: list[bytes] | None = None,
            timeout: float = 600.0,
        ) -> bytes | None:
            return None

    with patch("icopykey.cli.nfc_reader._KEY_RECOVERY_CLASSES", (FakeUnavailable,)):
        assert auto_key_recovery_source() is None
