"""Tests for the external NFC reader interface."""

from icopykey.cli.nfc_reader import (
    NfcReader,
    PcscReader,
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
    import pytest
    with pytest.raises(TypeError):
        NfcReader()  # type: ignore
