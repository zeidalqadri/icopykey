"""Minimal pcapng writer for CopyKEY HID self-recordings.

Produces files byte-compatible with the existing parser in
:func:`icopykey.cli.analyze_capture.parse_pcapng`.  Each captured frame
is encoded as a pcapng Enhanced Packet Block (type ``0x00000006``) whose
packet data is a USBPcap-v1-style header followed by the 64-byte HID
report.

Byte layout of one packet's captured data (91 bytes total):

    ┌──────────┬──────────────────────────────────────────────┐
    │ 0..1     │ hdr_len           uint16 LE   = 27           │
    │ 2..15    │ USBPcap fixed     14 bytes    zeros          │
    │ 16       │ info byte         uint8       0x00=OUT 0x01=IN│
    │ 17..26   │ USBPcap remainder 10 bytes    zeros          │
    │ 27..90   │ HID report        64 bytes                   │
    └──────────┴──────────────────────────────────────────────┘

Reader semantics confirmed in
``analyze_capture.parse_pcapng()`` lines 67-77:

* ``hdr_len`` must equal 27 ⇒ USBPcap v1 detection.
* Byte 16's bit 0 ⇒ direction (IN if set).
* HID payload at ``pkt_data[27:91]``.
* Only payloads whose first byte equals ``REPORT_PREFIX`` (0x95) are
  surfaced; non-protocol noise is silently dropped.

Pcapng padding: the per-block padding aligns the END of packet data to
4 bytes.  91-byte capture ⇒ 1 byte pad ⇒ block total length 124.

Reference: PCAP Next Generation File Format Specification
(https://github.com/IETF-OPSAWG-WG/pcapng).
"""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path

# Required to survive the analyze_capture filter at parse time.
_HID_FRAME_LEN = 64
_USBPCAP_HDR_LEN = 27
_CAPTURED_LEN = _USBPCAP_HDR_LEN + _HID_FRAME_LEN  # 91

# pcapng block-type constants
_BLOCK_SHB = 0x0A0D0D0A
_BLOCK_IDB = 0x00000001
_BLOCK_EPB = 0x00000006

# LinkType 220 = LINKTYPE_USBPCAP per IANA registry. The reader doesn't
# consult this, but Wireshark / tshark do; include it so external tools
# pick up the right dissector if a user opens the file in Wireshark.
_LINKTYPE_USBPCAP = 220


class PcapNgWriter:
    """Stream pcapng frames out to a file as captures arrive.

    Single-writer, single-file.  Not thread-safe — wrap in a lock if you
    need concurrent writes.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "wb")
        self.frames_written = 0
        self._closed = False
        self._write_shb()
        self._write_idb()

    # ── public API ──────────────────────────────────────────────

    def write_frame(self, direction: str, payload: bytes) -> None:
        """Append one HID frame.

        Parameters
        ----------
        direction : str
            Either ``"OUT"`` or ``"IN"``.
        payload : bytes
            Exactly 64 bytes — the HID report as the device sends/receives
            it on the wire.
        """
        if self._closed:
            raise ValueError("writer is closed")
        if direction not in ("OUT", "IN"):
            raise ValueError(f"direction must be 'OUT' or 'IN', got {direction!r}")
        if len(payload) != _HID_FRAME_LEN:
            raise ValueError(
                f"payload must be exactly {_HID_FRAME_LEN} bytes, got {len(payload)}"
            )
        self._write_epb(direction, payload)
        self.frames_written += 1

    def close(self) -> None:
        if self._closed:
            return
        self._fh.flush()
        self._fh.close()
        self._closed = True

    def __enter__(self) -> "PcapNgWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def path(self) -> Path:
        return self._path

    # ── block writers (pcapng spec) ──────────────────────────────

    def _write_shb(self) -> None:
        """Section Header Block — required first block of any pcapng file."""
        # Block layout (28 bytes total):
        #   0..4   block_type            = 0x0A0D0D0A
        #   4..8   block_total_length    = 28
        #   8..12  byte_order_magic      = 0x1A2B3C4D
        #   12..14 major_version         = 1
        #   14..16 minor_version         = 0
        #   16..24 section_length        = -1 (uint64, unknown)
        #   24..28 block_total_length    = 28
        total = 28
        body = struct.pack(
            "<I I I H H q I",
            _BLOCK_SHB,
            total,
            0x1A2B3C4D,
            1,
            0,
            -1,
            total,
        )
        self._fh.write(body)

    def _write_idb(self) -> None:
        """Interface Description Block — one per capture interface."""
        # Block layout (20 bytes total — no options):
        #   0..4   block_type            = 0x00000001
        #   4..8   block_total_length    = 20
        #   8..10  link_type             = 220 (LINKTYPE_USBPCAP)
        #   10..12 reserved              = 0
        #   12..16 snaplen               = _CAPTURED_LEN (91)
        #   16..20 block_total_length    = 20
        total = 20
        body = struct.pack(
            "<I I H H I I",
            _BLOCK_IDB,
            total,
            _LINKTYPE_USBPCAP,
            0,
            _CAPTURED_LEN,
            total,
        )
        self._fh.write(body)

    def _write_epb(self, direction: str, payload: bytes) -> None:
        """Enhanced Packet Block — one per captured frame."""
        # Captured packet data (91 bytes):
        #   USBPcap-v1 header (27 bytes) + HID payload (64 bytes)
        info_byte = 0x01 if direction == "IN" else 0x00
        usbpcap_hdr = bytearray(_USBPCAP_HDR_LEN)
        struct.pack_into("<H", usbpcap_hdr, 0, _USBPCAP_HDR_LEN)
        usbpcap_hdr[16] = info_byte
        # Bytes 2..15 and 17..26 stay zero; the reader ignores them.

        pkt_data = bytes(usbpcap_hdr) + payload
        assert len(pkt_data) == _CAPTURED_LEN

        # Pcapng requires packet data to be padded to a 4-byte boundary
        # AFTER the captured-data field.  91 % 4 == 3 ⇒ 1 byte of pad.
        pad_len = (-_CAPTURED_LEN) % 4  # = 1

        # Block layout:
        #   0..4   block_type             = 0x00000006
        #   4..8   block_total_length     = 8 + 20 + 91 + 1 + 4 = 124
        #   8..12  interface_id           = 0
        #   12..16 timestamp_high         = (us >> 32) & 0xFFFFFFFF
        #   16..20 timestamp_low          = us & 0xFFFFFFFF
        #   20..24 captured_packet_length = 91
        #   24..28 original_packet_length = 91
        #   28..119 packet_data            (91 bytes)
        #   119..120 padding              (1 byte)
        #   120..124 block_total_length    = 124
        total = 8 + 20 + _CAPTURED_LEN + pad_len + 4

        ts_us = int(time.time() * 1_000_000)
        ts_high = (ts_us >> 32) & 0xFFFFFFFF
        ts_low = ts_us & 0xFFFFFFFF

        header = struct.pack(
            "<I I I I I I I",
            _BLOCK_EPB,
            total,
            0,
            ts_high,
            ts_low,
            _CAPTURED_LEN,
            _CAPTURED_LEN,
        )
        trailer = struct.pack("<I", total)

        self._fh.write(header)
        self._fh.write(pkt_data)
        if pad_len:
            self._fh.write(b"\x00" * pad_len)
        self._fh.write(trailer)
