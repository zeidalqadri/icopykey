"""
Tests for the real CopyKEY X100 HID report protocol (_protocol.py).
Validates frame format, parse round-trip, and ground-truth templates from USBPcap capture.
"""

import struct

import pytest

from icopykey.cli._protocol import (
    REPORT_SIZE,
    REPORT_PREFIX,
    PAYLOAD_SIZE,
    CMD_PROBE,
    CMD_SECTOR_OP,
    CMD_DATA_RESPONSE,
    CMD_IDLE,
    CMD_DEVICE_INFO,
    CMD_DEVICE_INFO_RESP,
    CMD_DEVICE_VERSION,
    CMD_DEVICE_ECHO,
    CMD_WRITE,
    CMD_WRITE_ACK,
    build_frame,
    parse_report,
    build_idle_frame,
    build_probe_frame,
    build_sector_read_frame,
    classify_payload,
    extract_sector_data,
    TEMPLATES,
    RESPONSES,
)


# ── Frame build / parse round-trip ───────────────────────────────────────────

def test_report_size():
    """64-byte HID report = 0x95 prefix + 3 * 21B payload."""
    assert REPORT_SIZE == 64
    assert 1 + 3 * 21 == 64
    assert PAYLOAD_SIZE == 21


def test_build_idle_frame_shape():
    """Idle frame must be 64 bytes with 0x95 prefix."""
    frame = build_idle_frame()
    assert len(frame) == REPORT_SIZE
    assert frame[0] == REPORT_PREFIX


def test_build_parse_roundtrip():
    """build_frame → parse_report must recover the payload."""
    payload = bytes(bytearray(range(21)))  # 0x00 0x01 ... 0x14
    frame = build_frame(payload)
    assert len(frame) == REPORT_SIZE
    assert frame[0] == REPORT_PREFIX

    recovered = parse_report(frame)
    assert recovered == payload


def test_parse_rejects_wrong_size():
    with pytest.raises(ValueError, match="must be 64"):
        parse_report(b"\x95" + b"A" * 20)


def test_parse_rejects_bad_prefix():
    with pytest.raises(ValueError, match="invalid report prefix"):
        parse_report(b"\x00" + b"A" * 63)


def test_build_rejects_wrong_payload_size():
    with pytest.raises(ValueError, match="payload must be 21"):
        build_frame(b"\x00" * 10)


# ── Rotational redundancy (OUT frames) ──────────────────────────────────────

def test_rotational_redundancy():
    """OUT frames repeat the 21B payload 3x with byte rotation."""
    payload = bytes(range(21))  # 0x00..0x14
    frame = build_frame(payload)

    seg0 = frame[1:22]          # bytes 1-21
    seg1 = frame[22:43]         # bytes 22-42
    seg2 = frame[43:64]         # bytes 43-63

    assert seg0 == payload

    expected_seg1 = payload[1:] + payload[:1]
    expected_seg2 = payload[2:] + payload[:2]

    assert seg1 == expected_seg1
    assert seg2 == expected_seg2


# ── Command constants ────────────────────────────────────────────────────────

def test_command_uniqueness():
    """All command bytes must be distinct."""
    commands = {
        CMD_PROBE, CMD_SECTOR_OP, CMD_DATA_RESPONSE, CMD_IDLE,
        CMD_DEVICE_INFO, CMD_DEVICE_INFO_RESP, CMD_DEVICE_VERSION,
        CMD_DEVICE_ECHO, CMD_WRITE, CMD_WRITE_ACK,
    }
    assert len(commands) == 10


def test_command_byte_range():
    """All commands must be valid 8-bit values."""
    for cmd in (CMD_PROBE, CMD_SECTOR_OP, CMD_DATA_RESPONSE, CMD_IDLE,
                CMD_DEVICE_INFO, CMD_DEVICE_INFO_RESP, CMD_DEVICE_VERSION,
                CMD_DEVICE_ECHO, CMD_WRITE, CMD_WRITE_ACK):
        assert 0 <= cmd <= 0xFF


# ── Template integrity (ground truth from USBPcap capture) ──────────────────

def test_templates_are_21_bytes():
    for name, payload in TEMPLATES.items():
        assert len(payload) == PAYLOAD_SIZE, f"template {name} must be {PAYLOAD_SIZE} bytes"


def test_responses_are_21_bytes():
    for name, payload in RESPONSES.items():
        assert len(payload) == PAYLOAD_SIZE, f"response {name} must be {PAYLOAD_SIZE} bytes"


def test_template_probe_has_correct_cmd():
    assert TEMPLATES["probe"][0] == CMD_PROBE


def test_template_sector_read_has_correct_cmd():
    assert TEMPLATES["sector_read"][0] == CMD_SECTOR_OP


def test_response_probe_ack_cmd():
    assert RESPONSES["probe_ack"][0] == CMD_PROBE


def test_response_sector_read_ack_cmd():
    assert RESPONSES["sector_read_ack"][0] == CMD_SECTOR_OP


def test_response_sector_data_cmd():
    assert RESPONSES["sector_data"][0] == CMD_SECTOR_OP


def test_response_write_ack_cmd():
    assert RESPONSES["write_ack"][0] == CMD_WRITE_ACK


# ── Payload classification ──────────────────────────────────────────────────

def test_classify_idle():
    payload = bytes.fromhex("d9d0c6cfc8cdedb7e2c2cac3d5dcdbdefea4f1d1d9")
    assert classify_payload(payload) == "idle"


def test_classify_probe_ack():
    assert classify_payload(RESPONSES["probe_ack"]) == "probe_ack"


def test_classify_sector_ack():
    assert classify_payload(RESPONSES["sector_read_ack"]) == "sector_ack"


def test_classify_sector_data():
    assert classify_payload(RESPONSES["sector_data"]) == "sector_data"


def test_classify_write_ack():
    assert classify_payload(RESPONSES["write_ack"]) == "write_ack"


def test_classify_unknown():
    payload = bytes([0xFF]) + b"\x00" * 20
    assert classify_payload(payload) == "unknown"


def test_classify_data_response():
    payload = bytes([CMD_DATA_RESPONSE]) + b"\x00" * 20
    assert classify_payload(payload) == "data_response"


# ── sector_data extraction ──────────────────────────────────────────────────

def test_extract_sector_data_from_sector_data_response():
    payload = bytearray(RESPONSES["sector_data"])
    payload[0] = CMD_SECTOR_OP
    sector, data = extract_sector_data(bytes(payload))
    assert isinstance(sector, int)
    assert isinstance(data, bytes)
    assert len(data) == 4


def test_extract_sector_data_wrong_cmd_returns_empty():
    payload = bytes([CMD_IDLE]) + b"\x00" * 20
    sector, data = extract_sector_data(payload)
    assert sector == 0
    assert data == b""


# ── Frame construction with parameters ──────────────────────────────────────

def test_build_probe_frame_shape():
    frame = build_probe_frame(sector_id=1, key_type=0x60)
    assert len(frame) == REPORT_SIZE
    assert frame[0] == REPORT_PREFIX

    payload = parse_report(frame)
    assert payload[0] == CMD_PROBE


def test_build_probe_frame_default():
    frame = build_probe_frame()
    assert len(frame) == REPORT_SIZE


def test_build_sector_read_frame_with_key():
    key = bytes.fromhex("A0A1A2A3A4A5")
    frame = build_sector_read_frame(sector=3, key=key)
    assert len(frame) == REPORT_SIZE
    assert frame[0] == REPORT_PREFIX

    payload = parse_report(frame)
    assert payload[0] == CMD_SECTOR_OP


def test_build_sector_read_frame_default_key():
    frame = build_sector_read_frame(sector=0)
    assert len(frame) == REPORT_SIZE

    payload = parse_report(frame)
    assert payload[0] == CMD_SECTOR_OP


def test_build_sector_read_frame_rejects_bad_key():
    with pytest.raises(ValueError, match="key must be 6"):
        build_sector_read_frame(sector=0, key=b"\x00" * 3)

# ── XOR-obfuscation property ──────────────────────────────────────────────

def test_probe_template_xor_has_header_pattern():
    """OUT probe always has cmd+44525b0c header (XOR-obfuscated)."""
    payload = TEMPLATES["probe"]
    assert payload[0] == CMD_PROBE
    assert payload[1:5] == bytes.fromhex("44525b0c")


def test_probe_response_xor_has_header_pattern():
    """IN probe_ack always has cmd+144241XX header (XOR-obfuscated)."""
    payload = RESPONSES["probe_ack"]
    assert payload[0] == CMD_PROBE
    assert payload[1:5] == bytes.fromhex("14424116")


# ── F8 / 0xDF bulk data commands (Phase 1) ──────────────────────────────────

def test_bulk_data_constant():
    from icopykey.cli._protocol import CMD_BULK_DATA
    assert CMD_BULK_DATA == 0xF8


def test_bulk_session_constant():
    from icopykey.cli._protocol import CMD_BULK_SESSION
    assert CMD_BULK_SESSION == 0xDF


def test_f8_templates_exist():
    from icopykey.cli._protocol import F8_TEMPLATES
    assert "bulk_read" in F8_TEMPLATES
    assert "session_init" in F8_TEMPLATES
    assert len(F8_TEMPLATES["bulk_read"]) == PAYLOAD_SIZE
    assert len(F8_TEMPLATES["session_init"]) == PAYLOAD_SIZE
    assert F8_TEMPLATES["bulk_read"][0] == 0xF8
    assert F8_TEMPLATES["session_init"][0] == 0xDF


def test_idle_plaintext():
    from icopykey.cli._protocol import IDLE_PLAINTEXT
    assert len(IDLE_PLAINTEXT) == PAYLOAD_SIZE
    assert IDLE_PLAINTEXT[0] == CMD_IDLE


def test_bulk_data_ack_response():
    from icopykey.cli._protocol import RESPONSES as R
    assert "bulk_data_ack" in R
    ack = R["bulk_data_ack"]
    assert len(ack) == PAYLOAD_SIZE
    assert ack[0] == 0xF8
    assert ack[1:8] == bytes.fromhex("f1e7eee9eccc96")


def test_classify_bulk_data_ack():
    from icopykey.cli._protocol import classify_payload, RESPONSES as R
    result = classify_payload(R["bulk_data_ack"])
    assert result == "bulk_data_ack"


def test_classify_session_init():
    from icopykey.cli._protocol import classify_payload, F8_TEMPLATES
    result = classify_payload(F8_TEMPLATES["session_init"])
    assert result == "session_init"


def test_derive_session_key_from_idle_pair():
    from icopykey.cli._protocol import derive_session_key, IDLE_PLAINTEXT
    out_idle = bytes.fromhex("d9d0c6cfc8cdedb7e2c2cac3d5dcdbdefea4f1d1d9")
    in_idle = bytes.fromhex("d9c0eaf606a0c09acd6a48ba99909792b2e8bd9db5")
    key = derive_session_key(out_idle, in_idle, IDLE_PLAINTEXT)
    assert len(key) == PAYLOAD_SIZE
    assert key[0] == 0x00
    for i in range(PAYLOAD_SIZE):
        assert out_idle[i] ^ key[i] == IDLE_PLAINTEXT[i]


def test_derive_session_key_defaults_to_idle():
    from icopykey.cli._protocol import derive_session_key, IDLE_PLAINTEXT
    out_idle = bytes.fromhex("d9d0c6cfc8cdedb7e2c2cac3d5dcdbdefea4f1d1d9")
    in_idle = bytes.fromhex("d9c0eaf606a0c09acd6a48ba99909792b2e8bd9db5")
    key = derive_session_key(out_idle, in_idle)
    assert len(key) == PAYLOAD_SIZE
    for i in range(PAYLOAD_SIZE):
        assert out_idle[i] ^ key[i] == IDLE_PLAINTEXT[i]


def test_build_bulk_read_frame_shape():
    from icopykey.cli._protocol import build_bulk_read_frame
    key = bytes.fromhex("A0A1A2A3A4A5")
    frame = build_bulk_read_frame(sector=3, key=key)
    assert len(frame) == REPORT_SIZE
    assert frame[0] == REPORT_PREFIX
    payload = parse_report(frame)
    assert payload[0] == 0xF8


def test_build_bulk_read_frame_with_session_key():
    from icopykey.cli._protocol import build_bulk_read_frame
    key = bytes.fromhex("FFFFFFFFFFFF")
    session_key = bytes(range(21))
    frame = build_bulk_read_frame(sector=5, key=key, session_key=session_key)
    assert len(frame) == REPORT_SIZE


def test_build_bulk_read_frame_rejects_bad_key():
    from icopykey.cli._protocol import build_bulk_read_frame
    with pytest.raises(ValueError, match="key must be 6"):
        build_bulk_read_frame(sector=0, key=b"\x00" * 3)


def test_build_session_init_frame_shape():
    from icopykey.cli._protocol import build_session_init_frame
    frame = build_session_init_frame()
    assert len(frame) == REPORT_SIZE
    assert frame[0] == REPORT_PREFIX
    payload = parse_report(frame)
    assert payload[0] == 0xDF


def test_build_session_init_frame_with_key():
    from icopykey.cli._protocol import build_session_init_frame
    key = bytes(range(21))
    frame = build_session_init_frame(session_key=key)
    assert len(frame) == REPORT_SIZE


# ── Segment XOR delta and full-frame parsing (Phase 2) ──────────────────────

def test_segment_xor_delta_length():
    from icopykey.cli._protocol import SEGMENT_XOR_DELTA
    assert len(SEGMENT_XOR_DELTA) == 19


def test_segment_xor_delta_structure():
    from icopykey.cli._protocol import SEGMENT_XOR_DELTA
    assert SEGMENT_XOR_DELTA[:2] == bytes.fromhex("1609")
    assert SEGMENT_XOR_DELTA[2:4] == bytes.fromhex("0705")


def test_parse_full_frame_returns_three_segments():
    from icopykey.cli._protocol import parse_full_frame, build_idle_frame
    frame = build_idle_frame()
    seg0, seg1, seg2 = parse_full_frame(frame)
    assert len(seg0) == 21
    assert len(seg1) == 21
    assert len(seg2) == 21
    assert seg0[0] == CMD_IDLE


def test_parse_full_frame_rejects_wrong_size():
    from icopykey.cli._protocol import parse_full_frame
    with pytest.raises(ValueError):
        parse_full_frame(b"\x95" + b"A" * 20)


def test_parse_full_frame_rejects_bad_prefix():
    from icopykey.cli._protocol import parse_full_frame
    with pytest.raises(ValueError):
        parse_full_frame(b"\x00" + b"A" * 63)


def test_validate_frame_idle():
    from icopykey.cli._protocol import validate_frame, build_idle_frame
    frame = build_idle_frame()
    valid, matches = validate_frame(frame)
    assert isinstance(valid, bool)
    assert isinstance(matches, int)


def test_validate_frame_bad_data():
    from icopykey.cli._protocol import validate_frame
    valid, matches = validate_frame(b"\x95" + b"\x00" * 63)
    assert not valid
    assert matches == 0


def test_extract_f8_data_dominant_ack():
    from icopykey.cli._protocol import extract_f8_data, RESPONSES
    ack = RESPONSES["bulk_data_ack"]
    frame = build_frame(ack)
    sector, seg0, delta = extract_f8_data(frame)
    assert sector == 0
    assert seg0 == b""


def test_extract_f8_data_non_ack():
    from icopykey.cli._protocol import extract_f8_data, build_frame
    payload = bytes([0xF8]) + bytes.fromhex("01102233445566778899aabbccddeeff00112233")
    frame = build_frame(payload)
    sector, seg0, delta = extract_f8_data(frame)
    assert sector == payload[5]
    assert seg0 == payload
    assert len(delta) == 21


def test_extract_f8_segment_data_returns_three_segments():
    from icopykey.cli._protocol import extract_f8_segment_data, RESPONSES
    ack = RESPONSES["bulk_data_ack"]
    frame = build_frame(ack)
    sector, s0, s1, s2 = extract_f8_segment_data(frame)
    assert sector == 0
    assert s0 == b""


def test_f8_xor_segments_verify_delta():
    """Verify XOR(seg1,seg2) matches SEGMENT_XOR_DELTA for first 19 bytes."""
    from icopykey.cli._protocol import SEGMENT_XOR_DELTA, RESPONSES, compute_xor
    ack = RESPONSES["bulk_data_ack"]
    seg1 = ack[1:] + ack[:1]  # rotL1
    seg2 = ack[2:] + ack[:2]  # rotL2
    xor_seg12 = compute_xor(seg1, seg2)
    assert len(xor_seg12) == 21
    assert xor_seg12[:19] == SEGMENT_XOR_DELTA[:19]
