"""Backward-compatible re-exports from the broken-out modules.

Canonical locations:
    .constants     — DEVICE_VID, DEVICE_PID, DEFAULT_KEYS, ...
    .vault         — AESVault
    .mifare_data   — MifareSector, MifareCard
    .device        — CopyKeyDevice, CopyKeyRemoteDevice
    .card_ops      — CardOperations
    .library       — LocalLibrary
    .crypto1_cipher — Crypto1, AccessCondition, SectorKeyInfo
"""

from __future__ import annotations

from .constants import (
    DEVICE_VID,
    DEVICE_PID,
    DEVICE_USAGE_PAGE,
    REPORT_SIZE_IN,
    REPORT_SIZE_OUT,
    FEATURE_REPORT_ID,
    RESPONSE_REPORT_ID,
    DEFAULT_KEYS,
)
from .vault import AESVault, CRYPTO_AVAILABLE
from .mifare_data import MifareSector, MifareCard, NtagCard, DesfireCard
from .device import CopyKeyDevice, CopyKeyRemoteDevice, HID_AVAILABLE
from .card_ops import CardOperations
from .library import LocalLibrary
from .crypto1_cipher import Crypto1, AccessCondition, SectorKeyInfo
