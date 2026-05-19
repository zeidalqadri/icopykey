"""Tests for the external NFC reader interface."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from icopykey.cli.nfc_reader import (
    LibNfcCLINonceSource,
    NfcReader,
    NfcpyNonceSource,
    NonceSource,
    PcscReader,
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
