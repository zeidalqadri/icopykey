"""
Shared TCP HID relay protocol constants and frame helpers.

Used by both ``hidrelay.py`` (server) and ``device.py`` (client).
Stdlib only — does not depend on hidapi or any other external library.
"""

from __future__ import annotations

import logging
import socket
import struct

logger = logging.getLogger("relay_protocol")

MSG_ENUMERATE = 0x01
MSG_OPEN = 0x02
MSG_WRITE_READ = 0x03
MSG_GET_DESCRIPTOR = 0x04
MSG_CLOSE = 0x05
MSG_READ_ONLY = 0x06
MSG_GET_INPUT_REPORT = 0x07
MSG_SET_FEATURE_REPORT = 0x08

HID_REPORT_SIZE = 64
HEADER_SIZE = 5
MAX_PAYLOAD = 1_048_576


def recv_frame(sock: socket.socket, timeout: float = 10.0) -> tuple[int, bytes] | None:
    """Receive a single framed message.  Returns (msg_type, payload) or None."""
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < HEADER_SIZE:
            chunk = sock.recv(HEADER_SIZE - len(header))
            if not chunk:
                return None
            header += chunk
    except (socket.timeout, OSError):
        return None

    msg_type = header[0]
    payload_len = struct.unpack(">I", header[1:5])[0]

    if payload_len > MAX_PAYLOAD:
        logger.error("Payload too large: %d", payload_len)
        return None

    payload = b""
    while len(payload) < payload_len:
        chunk = sock.recv(payload_len - len(payload))
        if not chunk:
            return None
        payload += chunk

    return msg_type, payload


def send_frame(sock: socket.socket, msg_type: int, payload: bytes) -> bool:
    """Send a framed message.  Returns True on success."""
    header = struct.pack(">BI", msg_type, len(payload))
    try:
        sock.sendall(header + payload)
        return True
    except OSError as e:
        logger.error("Send failed: %s", e)
        return False
