"""
Tests for display and error formatting.

Validates that display functions run without exceptions and produce
expected output patterns.
"""

from __future__ import annotations

import io
import sys
import pytest

from ..display import (
    print_success,
    print_error,
    print_warning,
    print_info,
    print_header,
    print_divider,
    print_table,
    print_card_info,
    print_status_line,
    print_key_value,
    strip_colors,
    RICH_AVAILABLE,
)
from ..errors import (
    CopyKeyError,
    DeviceNotFoundError,
    DeviceTimeoutError,
    ValidationError,
    InvalidHexError,
    InvalidKeyError,
    VaultAccessError,
)


class TestDisplayFunctions:
    """Tests that all display functions execute without raising."""

    @pytest.fixture(autouse=True)
    def capture_output(self) -> io.StringIO:
        old = sys.stdout
        buf = io.StringIO()
        sys.stdout = buf
        yield buf
        sys.stdout = old

    def test_print_success(self) -> None:
        print_success("Operation completed")
        # Should not raise

    def test_print_error(self) -> None:
        print_error("Something failed")
        # Should not raise

    def test_print_warning(self) -> None:
        print_warning("Proceed with caution")
        # Should not raise

    def test_print_info(self) -> None:
        print_info("Informational message")
        # Should not raise

    def test_print_header_basic(self) -> None:
        print_header("Test Header")
        # Should not raise

    def test_print_header_with_subtitle(self) -> None:
        print_header("Main Title", "Subtitle line")
        # Should not raise

    def test_print_divider(self) -> None:
        print_divider("Section")
        # Should not raise

    def test_print_divider_empty(self) -> None:
        print_divider()
        # Should not raise

    def test_print_table(self) -> None:
        print_table(
            ["Col1", "Col2"],
            [["a", "1"], ["b", "2"]],
            title="Test Table",
        )
        # Should not raise

    def test_print_table_empty(self) -> None:
        print_table(["Col"], [], "Empty")
        # Should not raise

    def test_print_card_info(self) -> None:
        print_card_info("4B2AF753", 0x08, "0400", "MIFARE Classic 1K")
        # Should not raise

    def test_print_status_line(self) -> None:
        print_status_line("Connected", "5 keys, 3 cards")
        # Should not raise

    def test_print_key_value(self) -> None:
        print_key_value("UID", "4B2AF753")
        # Should not raise


class TestErrorMessages:
    def test_device_not_found(self) -> None:
        err = DeviceNotFoundError(vid=0x0483, pid=0x5740)
        s = str(err)
        assert "0x0483" in s
        assert "0x5740" in s
        assert "Hint:" in s

    def test_device_timeout(self) -> None:
        err = DeviceTimeoutError("read_sector", 3000)
        assert "read_sector" in str(err)
        assert "3000ms" in str(err)

    def test_invalid_hex(self) -> None:
        err = InvalidHexError("ZZ", "key")
        assert "ZZ" in str(err)
        assert "key" in str(err)

    def test_invalid_key(self) -> None:
        err = InvalidKeyError("SHORT")
        assert "SHORT" in str(err)
        assert "12" in str(err)  # hex digits

    def test_vault_access(self) -> None:
        err = VaultAccessError()
        assert "password" in str(err).lower()

    def test_base_error_no_hint(self) -> None:
        err = CopyKeyError("Simple error")
        assert str(err) == "Simple error"

    def test_validation_error(self) -> None:
        err = ValidationError("Bad input", hint="Try again")
        assert "Bad input" in str(err)
        assert "Try again" in str(err)


class TestStripColors:
    def test_no_colors(self) -> None:
        assert strip_colors("plain text") == "plain text"

    def test_ansi_escape_stripped(self) -> None:
        colored = "\033[32;1mSuccess!\033[0m"
        assert strip_colors(colored) == "Success!"
