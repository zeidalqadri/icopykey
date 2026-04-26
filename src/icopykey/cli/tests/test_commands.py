"""
Tests for CLI commands.

Tests command handlers with mocked device and library objects.
"""

from __future__ import annotations

import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ..operations import (
    CopyKeyDevice,
    CardOperations,
    LocalLibrary,
    MifareCard,
    MifareSector,
)
from ..commands import (
    CommandResult,
    cmd_read_card,
    cmd_list_keys,
    cmd_add_key,
    cmd_del_key,
    cmd_list_cards,
    cmd_load_card,
    cmd_save_card,
    cmd_delete_card,
    cmd_export_card,
    cmd_import_card,
    cmd_device_info,
)
from ..errors import InvalidKeyError


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def mock_device() -> MagicMock:
    dev = MagicMock(spec=CopyKeyDevice)
    dev.is_connected.return_value = True
    dev.get_device_info.return_value = {
        "manufacturer": "TestMfg",
        "product": "TestProduct",
        "serial": "TEST001",
        "path": "/dev/test",
    }
    return dev


@pytest.fixture
def mock_ops(mock_device: MagicMock) -> CardOperations:
    ops = CardOperations(mock_device)
    return ops


@pytest.fixture
def sample_card() -> MifareCard:
    uid = bytes.fromhex("4B2AF753")
    card = MifareCard(uid=uid, sak=0x08, atqa=bytes.fromhex("0400"))
    for i in range(16):
        sector = MifareSector(i)
        sector.key_a = bytes.fromhex("FFFFFFFFFFFF")
        sector.key_b = bytes.fromhex("FFFFFFFFFFFF")
        card.set_sector(i, sector)
    return card


@pytest.fixture
def tmp_library(tmp_path: Path) -> LocalLibrary:
    return LocalLibrary(tmp_path, vault_password=None)


# ── Read Card ────────────────────────────────────────────────────


def test_cmd_read_card_success(mock_ops: CardOperations) -> None:
    mock_ops.device.read_card_info.return_value = {
        "uid": bytes.fromhex("4B2AF753"),
        "sak": 0x08,
        "atqa": bytes.fromhex("0400"),
        "card_type": "MIFARE Classic 1K",
    }
    result = cmd_read_card(mock_ops)
    assert result.success is True
    assert result.data is not None


def test_cmd_read_card_no_card(mock_ops: CardOperations) -> None:
    mock_ops.device.read_card_info.return_value = None
    result = cmd_read_card(mock_ops)
    assert result.success is False


# ── Key Library ──────────────────────────────────────────────────


def test_cmd_list_keys_empty(tmp_library: LocalLibrary) -> None:
    result = cmd_list_keys(tmp_library)
    assert result.success is True
    assert result.message == "Key library is empty"


def test_cmd_add_key_valid(tmp_library: LocalLibrary) -> None:
    result = cmd_add_key(tmp_library, "test_key", "FFFFFFFFFFFF")
    assert result.success is True
    assert "test_key" in tmp_library.keys


def test_cmd_add_key_invalid(tmp_library: LocalLibrary) -> None:
    result = cmd_add_key(tmp_library, "bad", "ZZZZ")
    assert result.success is False


def test_cmd_del_key_exists(tmp_library: LocalLibrary) -> None:
    tmp_library.add_key("test_key", bytes.fromhex("FFFFFFFFFFFF"))
    result = cmd_del_key(tmp_library, "test_key")
    assert result.success is True
    assert "test_key" not in tmp_library.keys


def test_cmd_del_key_not_found(tmp_library: LocalLibrary) -> None:
    result = cmd_del_key(tmp_library, "nonexistent")
    assert result.success is False


# ── Card Library ─────────────────────────────────────────────────


def test_cmd_list_cards_empty(tmp_library: LocalLibrary) -> None:
    result = cmd_list_cards(tmp_library)
    assert result.success is True
    assert result.message == "Card library is empty"


def test_cmd_save_and_load_card(
    tmp_library: LocalLibrary, mock_ops: CardOperations, sample_card: MifareCard
) -> None:
    mock_ops.current_card = sample_card
    result = cmd_save_card(tmp_library, mock_ops, "TestCard")
    assert result.success is True

    result = cmd_load_card(tmp_library, mock_ops, 0)
    assert result.success is True
    assert mock_ops.current_card is not None
    assert mock_ops.current_card.uid_hex == "4B2AF753"


def test_cmd_load_card_invalid_index(tmp_library: LocalLibrary, mock_ops: CardOperations) -> None:
    result = cmd_load_card(tmp_library, mock_ops, 999)
    assert result.success is False


def test_cmd_delete_card(
    tmp_library: LocalLibrary, mock_ops: CardOperations, sample_card: MifareCard
) -> None:
    mock_ops.current_card = sample_card
    cmd_save_card(tmp_library, mock_ops, "ToDelete")
    result = cmd_delete_card(tmp_library, 0)
    assert result.success is True


def test_cmd_export_card(
    tmp_library: LocalLibrary, mock_ops: CardOperations, sample_card: MifareCard, tmp_path: Path
) -> None:
    mock_ops.current_card = sample_card
    cmd_save_card(tmp_library, mock_ops, "ExportMe")
    out_dir = str(tmp_path)
    result = cmd_export_card(tmp_library, 0, out_dir)
    assert result.success is True
    assert (tmp_path / "ExportMe.json").exists()


def test_cmd_import_card_valid_json(
    tmp_library: LocalLibrary, mock_ops: CardOperations, sample_card: MifareCard, tmp_path: Path
) -> None:
    data = json.dumps(sample_card.to_dict(), indent=2)
    filepath = tmp_path / "import_test.json"
    filepath.write_text(data, encoding="utf-8")

    result = cmd_import_card(tmp_library, mock_ops, str(filepath))
    assert result.success is True
    cards = tmp_library.list_cards()
    assert len(cards) == 1


def test_cmd_import_card_missing_file(
    tmp_library: LocalLibrary, mock_ops: CardOperations
) -> None:
    result = cmd_import_card(tmp_library, mock_ops, "/nonexistent/card.json")
    assert result.success is False


# ── Device Info ──────────────────────────────────────────────────


def test_cmd_device_info_connected(mock_device: MagicMock) -> None:
    result = cmd_device_info(mock_device)
    assert result.success is True


def test_cmd_device_info_disconnected(mock_device: MagicMock) -> None:
    mock_device.is_connected.return_value = False
    result = cmd_device_info(mock_device)
    assert result.success is False


# ── CommandResult ────────────────────────────────────────────────


def test_command_result_success() -> None:
    cr = CommandResult(True, "ok", data={"key": "val"})
    assert cr.success
    assert cr.error is None
    assert cr.data == {"key": "val"}


def test_command_result_failure() -> None:
    cr = CommandResult(False, error="something went wrong")
    assert not cr.success
    assert cr.error == "something went wrong"
