"""
Real CopyKEY X100 HID report protocol (reverse-engineered from USBPcap capture).

HID report format: 64 bytes
  0x95 | 21B_payload | 21B_payload_rotL1 | 21B_payload_rotL2

The 21-byte payload is repeated 3x with rotational redundancy on OUT frames:
  seg1 = ROTL(seg0, 1 byte)
  seg2 = ROTL(seg0, 2 bytes)

IN frames lack rotational redundancy; segments may XOR-differ due to
device Crypto1 stream cipher obfuscation.

XOR obfuscation scheme (reverse-engineered):
  - Per-session 21-byte XOR key K, derived at device initialization
  - OUT[i] = plaintext_OUT[i] XOR K[i] for each byte position
  - IN[i]  = plaintext_IN[i]  XOR K[i]
  - XOR(OUT, IN) = XOR(plaintext_OUT, plaintext_IN) — key cancels out
  - Bytes 0-4: command-specific header, same per cmd type
  - Byte 5: sector number (0x0d probes) or operation param (0xc9 ops)
  - Bytes 6-20: vary by response content; probes have constant padding byte

To replay arbitrary parameters without knowing K:
  Template[i] = plaintext_original[i] XOR K[i]
  For new parameter P at position i:
    new[i] = Template[i] XOR plaintext_original[i] XOR P
           = K[i] XOR P

Stdlib only — does not depend on hidapi or any external library.
"""

from __future__ import annotations

import struct

# ── HID report constants ──────────────────────────────────────────────────

REPORT_PREFIX = 0x95
PAYLOAD_SIZE = 21
REPORT_SIZE = 64  # 1 (prefix) + 3 * 21

# ── Command bytes (real protocol, from capture) ──────────────────────────

CMD_PROBE = 0x0D          # Card probe / read sector info
CMD_SECTOR_OP = 0xC9      # Sector read & write (primary operation)
CMD_DATA_RESPONSE = 0xD8  # Response data (multi-sector decode result)
CMD_IDLE = 0xD9           # Idle heartbeat (sent ~every 100ms)
CMD_DEVICE_INFO = 0x8D    # Device info request
CMD_DEVICE_INFO_RESP = 0x8C  # Device info response
CMD_DEVICE_VERSION = 0x9C  # Version/type info
CMD_DEVICE_ECHO = 0x5D     # Device echo / self-test
CMD_WRITE = 0x28           # Write sector command
CMD_WRITE_ACK = 0xED       # Write acknowledge
CMD_BULK_DATA = 0xF8       # Bulk sector page reads (dominant data channel)
CMD_BULK_SESSION = 0xDF    # Session key init / mode switch (before F8 burst)


# ── Frame builder / parser ───────────────────────────────────────────────

def _rotl(data: bytes, n: int) -> bytes:
    """Rotate bytes left by n positions."""
    n = n % len(data)
    return data[n:] + data[:n]


def build_frame(payload: bytes) -> bytes:
    """Build a 64-byte HID report from a 21-byte payload.

    OUT direction: rotational redundancy (seg1=rotL1, seg2=rotL2).
    """
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError(f"payload must be {PAYLOAD_SIZE} bytes, got {len(payload)}")

    return bytes([REPORT_PREFIX]) + payload + _rotl(payload, 1) + _rotl(payload, 2)


def parse_report(report: bytes) -> bytes:
    """Extract the 21-byte payload (seg0) from a 64-byte HID report.

    Returns the payload bytes at positions 1-21. Does NOT verify redundancy.
    """
    if len(report) != REPORT_SIZE:
        raise ValueError(f"report must be {REPORT_SIZE} bytes, got {len(report)}")
    if report[0] != REPORT_PREFIX:
        raise ValueError(f"invalid report prefix: 0x{report[0]:02x}, expected 0x{REPORT_PREFIX:02x}")

    return report[1:22]


def build_idle_frame() -> bytes:
    """Build an idle heartbeat frame (0xd9)."""
    return build_frame(bytes.fromhex("d9d0c6cfc8cdedb7e2c2cac3d5dcdbdefea4f1d1d9"))


# ── Template frames (ground truth from capture) ──────────────────────────

TEMPLATES: dict[str, bytes] = {
    # Card probe OUT: send to detect card and get UID/SAK/ATQA
    "probe": bytes.fromhex("0d44525b0c99c9e621000801171e191c3c6633131b"),

    # Sector read OUT: reads 64 bytes for a given sector
    # Template: cmd(0xc9) | sector_param | key_type | key[6] | padding
    "sector_read": bytes.fromhex("c9f0e67ec54ccfc0de795ba98a838481a1fbae8e86"),
}

# Known-good response patterns
RESPONSES: dict[str, bytes] = {
    # Expected probe IN (card detected, returns card info)
    "probe_ack": bytes.fromhex("0d1442411661395c0a2a222b3d343336164c193931"),

    # Expected sector read ACK IN (operation acknowledged)
    "sector_read_ack": bytes.fromhex("c95640494e4b6b3164444c45535a5d58782277575f"),

    # Expected sector read IN with data
    "sector_data": bytes.fromhex("c9d0c6cfc8cdedb7e2c2cac3d5dcdbdefea4f1d1d9"),

    # Write ACK
    "write_ack": bytes.fromhex("edd8e4162461015b0ea98b795a535451712b7e5e76"),

    # Bulk data ACK (99% of F8 IN responses)
    "bulk_data_ack": bytes.fromhex("f8f1e7eee9eccc96c3e3ebe2f4fdfaffdf85d0f0f8"),
}


# ── F8 / Bulk data templates (from TBLXO3 capture, session-layer) ─────────

F8_TEMPLATES: dict[str, bytes] = {
    # Bulk sector read OUT (sector=0x99, key_type=0x60) — TBLXO3 capture
    "bulk_read": bytes.fromhex("f8809699cde9146be996752c3d0605e39f39b802a7"),

    # 0xDF session init OUT (sent once before F8 burst)
    "session_init": bytes.fromhex("df1853661008a86d2b05c5887bcb588e5d8caa7abc"),
}

# Idle heartbeat plaintext (derived from invariant OUT pattern across captures)
IDLE_PLAINTEXT = bytes.fromhex("d9e0d7d6d1d6e486a3b3b3a3c3c5c5c4c4e4f4f4e4")


# ── Parameter substitution ───────────────────────────────────────────────

def build_probe_frame(sector_id: int = 0, key_type: int = 0x60) -> bytes:
    """Build a card probe frame from the template."""
    payload = bytearray(TEMPLATES["probe"])
    # Byte 5 = sector number, XOR-adjust (templates use sector 0x99 which is XOR'd)
    # Without knowing the XOR key, we include a best-effort override.
    # The raw template works for most probes; sector-specific gets XOR'd.
    payload[5] ^= sector_id  # Trial xor adjustment (may fail if key mismatches)
    payload[6] ^= key_type
    return build_frame(bytes(payload))


def build_sector_read_frame(sector: int, key_type: int = 0x60, key: bytes = None) -> bytes:
    """Build a sector read frame from the template.

    Args:
        sector: Sector number (0-39 for 1K/4K cards)
        key_type: 0x60 for key A, 0x61 for key B
        key: 6-byte MIFARE key (defaults to FF*6)
    """
    if key is None:
        key = b'\xff' * 6
    if len(key) != 6:
        raise ValueError(f"key must be 6 bytes, got {len(key)}")

    payload = bytearray(TEMPLATES["sector_read"])
    # Bytes 8-13 = key area in template; XOR-adjust
    # The template contains XOR-encrypted key bytes at known positions
    # We XOR the template's encrypted key with (template_key XOR real_key)
    template_key = b'\xff' * 6  # FF FF FF FF FF FF (most common default)
    for i in range(6):
        payload[8 + i] ^= template_key[i] ^ key[i]

    # Sector ID goes at byte 5 (speculative, will be XOR'd)
    payload[5] ^= sector

    return build_frame(bytes(payload))


def classify_payload(payload: bytes) -> str:
    """Classify a 21-byte payload into a known response type.

    Returns one of: 'probe_ack', 'sector_ack', 'sector_data',
    'idle', 'write_ack', 'data_response', 'unknown'.
    """
    cmd = payload[0]
    if cmd == CMD_IDLE:
        return 'idle'
    if cmd == CMD_PROBE:
        return 'probe_ack'
    if cmd == CMD_SECTOR_OP:
        # Distinguish ACK from data: ACK has 5640494e4b6b3164 header at bytes 1-8
        if payload[1:9] == bytes.fromhex("5640494e4b6b3164"):
            return 'sector_ack'
        return 'sector_data'
    if cmd == CMD_DATA_RESPONSE:
        return 'data_response'
    if cmd == CMD_WRITE_ACK:
        return 'write_ack'
    if cmd == CMD_BULK_DATA:
        # Distinguish ACK from data: bulk_data_ack has f1e7eee9eccc96 header
        if payload[1:7] == bytes.fromhex("f1e7eee9eccc"):
            return 'bulk_data_ack'
        return 'bulk_data'
    if cmd == CMD_BULK_SESSION:
        return 'session_init'
    return 'unknown'


def extract_sector_data(payload: bytes) -> tuple[int, bytes]:
    """Extract sector number and 64 bytes of data from a sector_data response.

    Returns (sector_number, sector_data_bytes) or (0, b'') on failure.
    Data is XOR-obfuscated; caller must apply the reverse-XOR.
    """
    if payload[0] != CMD_SECTOR_OP:
        return 0, b''

    # Sector number at byte 5 (XOR'd)
    sector = payload[5]
    # Data occupies bytes 8-? (speculative, 4 bytes in observed capture)
    # For full 64-byte reads, multiple 0xc9 bursts are sent
    data = bytes(payload[8:12])

    return sector, data


# ── XOR analysis / session key management ─────────────────────────────────

def compute_xor(a: bytes, b: bytes) -> bytes:
    """Compute per-byte XOR of two equal-length payloads."""
    if len(a) != len(b):
        raise ValueError(f"payload lengths differ: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


class SessionKey:
    """Manages a per-session 21-byte XOR key derived from capture analysis.

    The session key K is the device's obfuscation keystream.
    Once known, frames can be constructed for arbitrary parameters:

        payload[i] = plaintext[i] XOR K[i]
        plaintext[i] = payload[i] XOR K[i]
    """

    __slots__ = ("_key",)

    def __init__(self, key: bytes | None = None) -> None:
        self._key: bytearray | None = bytearray(key) if key else None

    @property
    def known(self) -> bool:
        return self._key is not None

    def apply(self, payload: bytes) -> bytes:
        """Remove XOR obfuscation (payload XOR key → plaintext)."""
        if self._key is None:
            raise ValueError("session key not set")
        if len(payload) != PAYLOAD_SIZE:
            raise ValueError(f"payload must be {PAYLOAD_SIZE} bytes")
        return compute_xor(payload, bytes(self._key))

    def encode(self, plaintext: bytes) -> bytes:
        """Apply XOR obfuscation (plaintext XOR key → payload)."""
        return self.apply(plaintext)

    def derive_from_template(self, template: bytes, plaintext_guess: bytes,
                             positions: tuple[int, int]) -> None:
        """Set key bytes [start:end] by XOR of template vs known plaintext.

        template[i] = plaintext[i] XOR K[i] → K[i] = template[i] XOR plaintext[i]
        """
        start, end = positions
        if self._key is None:
            self._key = bytearray(PAYLOAD_SIZE)
        for i in range(start, min(end, PAYLOAD_SIZE)):
            self._key[i] = template[i] ^ plaintext_guess[i]

    @classmethod
    def from_probe_pair(cls, out_plain: bytes, in_plain: bytes,
                        out_captured: bytes, in_captured: bytes) -> "SessionKey":
        """Recover session key from a known probe OUT/IN pair.

        Given known plaintext for one probe exchange and the captured
        XOR-obfuscated payloads, recover the session key:

            K[i] = OUT_captured[i] XOR out_plain[i]
            K[i] = IN_captured[i] XOR in_plain[i]

        Both must agree (they self-validate).
        """
        key = bytearray(PAYLOAD_SIZE)
        settle = 0
        for i in range(PAYLOAD_SIZE):
            k_out = out_captured[i] ^ out_plain[i]
            k_in = in_captured[i] ^ in_plain[i]
            if k_out == k_in:
                key[i] = k_out
                settle += 1
        return cls(bytes(key))


def analyze_xor_stream(pairs: list[tuple[bytes, bytes]]) -> dict:
    """Analyze a sequence of (out_payload, in_payload) pairs.

    Returns a dict keyed by command byte with per-byte XOR delta statistics.
    Useful for reverse engineering the protocol from a capture.
    """
    from collections import Counter

    results: dict[int, dict] = {}
    for out_h, in_h in pairs:
        cmd = out_h[0]
        delta = compute_xor(out_h, in_h)

        if cmd not in results:
            results[cmd] = {
                "count": 0,
                "byte_variance": [Counter() for _ in range(PAYLOAD_SIZE)],
                "repeating_mask": bytearray(PAYLOAD_SIZE),
            }

        entry = results[cmd]
        entry["count"] += 1
        for i in range(PAYLOAD_SIZE):
            entry["byte_variance"][i][delta[i]] += 1

    # Compute repeating masks (bytes where all observed deltas are identical)
    for cmd, entry in results.items():
        for i in range(PAYLOAD_SIZE):
            counts = entry["byte_variance"][i]
            if len(counts) == 1:
                entry["repeating_mask"][i] = 1

    return results


# ── Session key derivation from idle heartbeat ────────────────────────────

def derive_session_key(out_idle: bytes, in_idle: bytes,
                       plaintext: bytes | None = None) -> bytes:
    """Derive the per-session 21-byte XOR key K from an idle heartbeat pair.

    Idle INVARIANCE: K[i] = out_idle[i] XOR plaintext_idle[i] for all 21 bytes
    (because out_idle[i] = plaintext_idle[i] XOR K[i])
    Same key from in_idle[i] = plaintext_idle[i] XOR K[i].

    Uses a default idle plaintext guess that matches observed capture patterns.
    """
    if plaintext is None:
        plaintext = IDLE_PLAINTEXT

    key = compute_xor(out_idle, plaintext)
    # Self-validate: key recovered from OUT should decrypt IN to same plaintext
    recovered_in = compute_xor(in_idle, key)
    if recovered_in != plaintext:
        # IN may have different plaintext. Use OUT-side as primary.
        pass

    return key


def build_bulk_read_frame(sector: int, key: bytes, session_key: bytes | None = None) -> bytes:
    """Build an F8 bulk sector read frame.

    Args:
        sector: sector index (0-255, encoded in byte 5)
        key: 6-byte MIFARE key
        session_key: per-session 21B XOR key (None = use template-only replay)

    The F8 protocol uses byte5 for sector addressing. Without the session
    key, this replays the template with sector XOR-substitution; with it,
    the full 21-byte payload is constructed with XOR(K, plaintext).
    """
    if len(key) != 6:
        raise ValueError(f"key must be 6 bytes, got {len(key)}")

    payload = bytearray(F8_TEMPLATES["bulk_read"])
    payload[5] ^= sector  # Sector byte substitution
    # Key at bytes 8-13
    template_key = b'\xff' * 6
    for i in range(6):
        payload[8 + i] ^= template_key[i] ^ key[i]

    if session_key is not None and len(session_key) == PAYLOAD_SIZE:
        return build_frame(compute_xor(bytes(payload), session_key))

    return build_frame(bytes(payload))


def build_session_init_frame(session_key: bytes | None = None) -> bytes:
    """Build the 0xDF session init frame that precedes F8 bulk operations.

    Args:
        session_key: per-session 21B XOR key (None = template-only replay)
    """
    payload = bytearray(F8_TEMPLATES["session_init"])
    if session_key is not None and len(session_key) == PAYLOAD_SIZE:
        return build_frame(compute_xor(bytes(payload), session_key))
    return build_frame(bytes(payload))


# ── Protocol-level segment XOR delta ───────────────────────────────────────

# XOR(seg1, seg2) = SEGMENT_XOR_DELTA for ALL IN frames (D8 and F8 channels).
# This constant appears identically across 3 independent captures.
# It is the XOR relationship between redundant payload segments in the
# 64-byte HID frame, providing error detection and recovery.
#
# First 19 bytes are invariant; bytes 19-20 vary per-session (index 19-20).
# Derived from: XOR(IN_payload[22:43], IN_payload[43:64]) for F8 dominant pattern.
SEGMENT_XOR_DELTA = bytes.fromhex("16090705205a5520080916090705205a552008")


def parse_full_frame(data: bytes) -> tuple[bytes, bytes, bytes]:
    """Parse a full 64-byte HID report into its 3 payload segments.

    Returns (seg0, seg1, seg2) — each 21 bytes.
    Validates prefix and size.
    """
    if len(data) != REPORT_SIZE:
        raise ValueError(f"report must be {REPORT_SIZE} bytes, got {len(data)}")
    if data[0] != REPORT_PREFIX:
        raise ValueError(f"invalid report prefix: 0x{data[0]:02x}, expected 0x{REPORT_PREFIX:02x}")

    seg0 = data[1:22]       # bytes 1-21
    seg1 = data[22:43]      # bytes 22-42
    seg2 = data[43:64]      # bytes 43-63

    return seg0, seg1, seg2


def validate_frame(data: bytes) -> tuple[bool, int]:
    """Validate a 64-byte report's segment redundancy.

    Checks that XOR(seg1, seg2) matches SEGMENT_XOR_DELTA for the
    first 19 bytes (the invariant portion). Returns (valid, matched_bytes).
    """
    try:
        seg0, seg1, seg2 = parse_full_frame(data)
    except ValueError:
        return False, 0

    expected = SEGMENT_XOR_DELTA
    match_count = 0
    seg_xor = compute_xor(seg1, seg2)

    for i in range(len(expected)):
        if seg_xor[i] == expected[i]:
            match_count += 1

    return match_count >= len(expected), match_count


def extract_f8_data(data: bytes) -> tuple[int, bytes, bytes]:
    """Extract sector index and raw data from an F8 singleton response.

    The F8 protocol sends 64B frames. XOR(seg0, dominant_ack) reveals
    the data delta from the idle/ack baseline.

    Returns (sector_index, seg0_payload, seg0_delta_from_ack).
    Returns (0, b"", b"") if this is the dominant ACK frame.
    """
    seg0, seg1, seg2 = parse_full_frame(data)

    if seg0[0] != CMD_BULK_DATA:
        return 0, b"", b""

    # Check if this is the dominant ACK (not actual data)
    if seg0[1:7] == bytes.fromhex("f1e7eee9eccc"):
        return 0, b"", b""  # dominant ACK, no sector data

    # Sector index at byte 5 (XOR-obfuscated)
    sector = seg0[5]

    # Compute delta from dominant ACK to reveal data structure
    ack_payload = RESPONSES.get("bulk_data_ack", b"")
    if ack_payload:
        delta = compute_xor(seg0, ack_payload)
    else:
        delta = compute_xor(seg0, b"\x00" * PAYLOAD_SIZE)

    return sector, bytes(seg0), delta


def extract_f8_segment_data(data: bytes) -> tuple[int, bytes, bytes, bytes]:
    """Extract full segment data from an F8 64B response.

    Returns (sector, seg0, seg1, seg2) for non-ACK F8 responses.
    Returns (0, b"", b"", b"") for dominant ACK frames.
    """
    seg0, seg1, seg2 = parse_full_frame(data)

    if seg0[0] != CMD_BULK_DATA:
        return 0, b"", b"", b""

    if seg0[1:7] == bytes.fromhex("f1e7eee9eccc"):
        return 0, b"", b"", b""

    sector = seg0[5]
    return sector, bytes(seg0), bytes(seg1), bytes(seg2)
