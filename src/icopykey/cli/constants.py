"""Device constants and default MIFARE Classic keys."""

from __future__ import annotations

DEVICE_VID = 0x6300
DEVICE_PID = 0x1991
DEVICE_USAGE_PAGE = 0xFF00
REPORT_SIZE_IN = 64
REPORT_SIZE_OUT = 64
FEATURE_REPORT_ID = 0x01
RESPONSE_REPORT_ID = 0x80

DEFAULT_KEYS: list[bytes] = [
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("B0B1B2B3B4B5"),
    bytes.fromhex("4D3A99C351DD"),
    bytes.fromhex("1A982C7E459A"),
    bytes.fromhex("D3F7D3F7D3F7"),
    bytes.fromhex("AABBCCDDEEFF"),
    bytes.fromhex("112233445566"),
    bytes.fromhex("654321FEDCBA"),
]
