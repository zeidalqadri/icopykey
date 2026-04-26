"""
Tests for CLI input validators.

Covers all validation functions with valid, invalid, and edge-case inputs.
"""

from __future__ import annotations

import pytest
from pathlib import Path
import tempfile
import os

from ..validators import (
    validate_hex,
    validate_key,
    validate_uid,
    validate_access_bits,
    validate_card_type,
    validate_vid_pid,
    validate_path,
    validate_filename,
    validate_choice,
    validate_integer,
    validate_index,
    validate_sector_numbers,
)
from ..errors import (
    InvalidHexError,
    InvalidKeyError,
    InvalidUIDError,
    InvalidAccessBitsError,
    InvalidCardTypeError,
)


class TestValidateHex:
    def test_valid_hex(self) -> None:
        assert validate_hex("ABCDEF") == "ABCDEF"

    def test_lowercase_normalized(self) -> None:
        assert validate_hex("abcdef") == "ABCDEF"

    def test_strips_colons(self) -> None:
        assert validate_hex("AB:CD:EF") == "ABCDEF"

    def test_strips_spaces(self) -> None:
        assert validate_hex("AB CD EF") == "ABCDEF"

    def test_strips_dashes(self) -> None:
        assert validate_hex("AB-CD-EF") == "ABCDEF"

    def test_empty_raises(self) -> None:
        with pytest.raises(InvalidHexError):
            validate_hex("")

    def test_invalid_chars_raises(self) -> None:
        with pytest.raises(InvalidHexError):
            validate_hex("GHIJKL")

    def test_non_hex_after_strip_raises(self) -> None:
        with pytest.raises(InvalidHexError):
            validate_hex("AB:CD:ZZ")


class TestValidateKey:
    def test_valid_6_byte_key(self) -> None:
        result = validate_key("FFFFFFFFFFFF")
        assert result == b"\xff" * 6

    def test_valid_key_with_colons(self) -> None:
        result = validate_key("FF:FF:FF:FF:FF:FF")
        assert result == b"\xff" * 6

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(InvalidKeyError):
            validate_key("FFFFFF")

    def test_invalid_hex_raises(self) -> None:
        with pytest.raises(InvalidKeyError):
            validate_key("ZZZZZZZZZZZZ")

    def test_custom_byte_length(self) -> None:
        result = validate_key("AABBCCDD", expected_bytes=4)
        assert result == bytes.fromhex("AABBCCDD")


class TestValidateUID:
    def test_valid_4_byte_uid(self) -> None:
        result = validate_uid("4B2AF753")
        assert len(result) == 4

    def test_valid_7_byte_uid(self) -> None:
        result = validate_uid("04112233445566")
        assert len(result) == 7

    def test_valid_10_byte_uid(self) -> None:
        result = validate_uid("AABBCCDDEEFF11223344")
        assert len(result) == 10

    def test_uid_with_colons(self) -> None:
        result = validate_uid("4B:2A:F7:53")
        assert len(result) == 4

    def test_invalid_length_raises(self) -> None:
        with pytest.raises(InvalidUIDError):
            validate_uid("ABCD")

    def test_non_hex_raises(self) -> None:
        with pytest.raises(InvalidUIDError):
            validate_uid("ZZZZZZZZ")


class TestValidateAccessBits:
    def test_valid_default(self) -> None:
        result = validate_access_bits("FF078069")
        assert len(result) == 4

    def test_valid_readonly(self) -> None:
        result = validate_access_bits("78778800")
        assert len(result) == 4

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(InvalidAccessBitsError):
            validate_access_bits("FF07")

    def test_non_hex_raises(self) -> None:
        with pytest.raises(InvalidAccessBitsError):
            validate_access_bits("ZZZZZZZZ")


class TestValidateCardType:
    def test_canonical_1k(self) -> None:
        assert validate_card_type("mifare_classic_1k") == "mifare_classic_1k"

    def test_alias_1k(self) -> None:
        assert validate_card_type("s50") == "mifare_classic_1k"

    def test_alias_id(self) -> None:
        assert validate_card_type("id") == "id_card"

    def test_alias_ntag(self) -> None:
        assert validate_card_type("ntag") == "ntag_ultralight"

    def test_spaces_normalized(self) -> None:
        assert validate_card_type("mifare 1k") == "mifare_classic_1k"

    def test_case_insensitive(self) -> None:
        assert validate_card_type("S50") == "mifare_classic_1k"

    def test_unknown_raises(self) -> None:
        with pytest.raises(InvalidCardTypeError):
            validate_card_type("desfire")


class TestValidateVIDPID:
    def test_valid_vid(self) -> None:
        assert validate_vid_pid("0483") == 0x0483

    def test_valid_with_0x_prefix(self) -> None:
        assert validate_vid_pid("0x0483") == 0x0483

    def test_empty_raises(self) -> None:
        with pytest.raises(InvalidHexError):
            validate_vid_pid("")

    def test_too_long_raises(self) -> None:
        with pytest.raises(InvalidHexError):
            validate_vid_pid("12345")


class TestValidatePath:
    def test_existing_file(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            f.flush()
            path = validate_path(f.name)
            assert path.exists()
            os.unlink(f.name)

    def test_non_existing_default(self) -> None:
        with pytest.raises(Exception):
            validate_path("/tmp/nonexistent_file_xyz_123")

    def test_non_existing_not_required(self) -> None:
        path = validate_path("/tmp/nonexistent_file_xyz_123", must_exist=False)
        assert not path.exists()

    def test_expands_user(self) -> None:
        path = validate_path("~/tmp_test_path", must_exist=False)
        assert str(path).startswith(str(Path.home()))


class TestValidateFilename:
    def test_normal_name(self) -> None:
        assert validate_filename("mycard.json") == "mycard.json"

    def test_strips_slashes(self) -> None:
        assert validate_filename("foo/bar.json") == "foo_bar.json"

    def test_strips_dotdot(self) -> None:
        assert validate_filename("../etc/passwd") == "__etc_passwd"

    def test_empty_returns_untitled(self) -> None:
        assert validate_filename("") == "untitled"


class TestValidateChoice:
    def test_valid_choice(self) -> None:
        assert validate_choice("a", ["a", "b", "c"]) == "a"

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_choice("x", ["a", "b"])

    def test_default(self) -> None:
        assert validate_choice("", ["a", "b"], default="a") == "a"


class TestValidateInteger:
    def test_valid(self) -> None:
        assert validate_integer("42") == 42

    def test_below_min_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_integer("-1", min_val=0)

    def test_above_max_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_integer("100", max_val=50)

    def test_not_integer_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_integer("abc")

    def test_within_range(self) -> None:
        assert validate_integer("5", min_val=0, max_val=10) == 5


class TestValidateIndex:
    def test_valid_index(self) -> None:
        assert validate_index("3", max_index=5) == 3

    def test_out_of_bounds_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_index("10", max_index=5)


class TestValidateSectorNumbers:
    def test_single_number(self) -> None:
        assert validate_sector_numbers("5", 16) == [5]

    def test_range(self) -> None:
        assert validate_sector_numbers("0-3", 16) == [0, 1, 2, 3]

    def test_comma_list(self) -> None:
        assert validate_sector_numbers("0,2,5", 16) == [0, 2, 5]

    def test_mixed(self) -> None:
        result = validate_sector_numbers("0,2-4,7", 16)
        assert result == [0, 2, 3, 4, 7]

    def test_out_of_bounds_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_sector_numbers("20", 16)

    def test_out_of_range_bounds_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_sector_numbers("0-20", 16)

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_sector_numbers("", 16)
