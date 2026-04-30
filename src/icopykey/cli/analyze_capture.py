"""
Capture analysis tool for CopyKEY X100 USB protocol reverse engineering.

Usage:
    python -m icopykey.cli.analyze_capture <pcapng_file>
    python -m icopykey.cli.analyze_capture --json <pcapng_file>
    python -m icopykey.cli.analyze_capture --compare <file1> <file2>

Parses USBPcap captures of X100 device traffic, extracts HID report pairs,
and performs XOR analysis to aid protocol reverse engineering.
"""

from __future__ import annotations

import json
import struct
import sys
from collections import Counter, defaultdict

from icopykey.cli._protocol import (
    PAYLOAD_SIZE,
    REPORT_PREFIX,
    REPORT_SIZE,
    compute_xor,
    analyze_xor_stream,
)

CMD_NAMES = {
    0x0D: "PROBE",
    0xC9: "SECTOR_OP",
    0xD9: "IDLE",
    0xD8: "DATA_RESPONSE",
    0x8D: "DEVICE_INFO",
    0x8C: "DEVICE_INFO_RESP",
    0x9C: "DEVICE_VERSION",
    0x5D: "DEVICE_ECHO",
    0x28: "WRITE",
    0xED: "WRITE_ACK",
    0xF8: "BULK_DATA",
    0xDF: "BULK_SESSION",
}


def parse_pcapng(path: str) -> list[tuple[str, bytes]]:
    """Parse a pcapng file, return [(direction, 64B_report), ...] for X100 HID frames."""
    with open(path, "rb") as f:
        data = f.read()

    pos = 0
    reports: list[tuple[str, bytes]] = []

    while pos < len(data):
        if pos + 8 > len(data):
            break
        block_type, block_total_length = struct.unpack("<II", data[pos : pos + 8])

        if block_type == 0x00000006:  # Enhanced Packet Block
            if pos + 32 > len(data):
                break
            captured_len = struct.unpack("<I", data[pos + 20 : pos + 24])[0]
            pkt_data_start = pos + 28
            if pkt_data_start + captured_len > len(data):
                break

            pkt_data = data[pkt_data_start : pkt_data_start + captured_len]

            if len(pkt_data) >= 27:
                hdr_len = struct.unpack("<H", pkt_data[0:2])[0]
                if hdr_len == 27:  # USBPcap v1
                    info_byte = pkt_data[16]
                    direction = "IN" if (info_byte & 1) else "OUT"
                    usb_data_len = captured_len - hdr_len

                    if usb_data_len >= 64:
                        payload = pkt_data[hdr_len : hdr_len + 64]
                        if payload[0] == REPORT_PREFIX:
                            reports.append((direction, payload))

            pos += block_total_length
        elif block_type in (0x0A0D0D0A, 0x00000001):
            pos += block_total_length
        else:
            pos += max(block_total_length, 8) if block_total_length > 0 else 8

    return reports


def pair_reports(reports: list[tuple[str, bytes]]) -> dict[int, list[tuple[bytes, bytes]]]:
    """Pair OUT->IN reports by command byte (sequential matching)."""
    pairs: dict[int, list[tuple[bytes, bytes]]] = defaultdict(list)

    i = 0
    while i < len(reports):
        d, p = reports[i]
        if d == "OUT":
            payload = p[1:22]
            cmd = payload[0]
            for j in range(i + 1, len(reports)):
                nd, np = reports[j]
                if nd == "IN":
                    npayload = np[1:22]
                    if npayload[0] == cmd:
                        pairs[cmd].append((payload, npayload))
                        i = j
                        break
        i += 1

    return dict(pairs)


def detect_cards(probe_pairs: list[tuple[bytes, bytes]]) -> list[dict]:
    """Group probe responses by card fingerprint (IN bytes[4:8]).

    Returns list of card records with fingerprint, count, sectors probed.
    """
    cards: dict[bytes, dict] = {}

    for out_h, in_h in probe_pairs:
        fingerprint = in_h[4:8]
        sector_byte = out_h[5]

        if fingerprint not in cards:
            cards[fingerprint] = {
                "fingerprint": fingerprint.hex(),
                "count": 0,
                "sectors": set(),
                "responses": Counter(),
            }

        cards[fingerprint]["count"] += 1
        cards[fingerprint]["sectors"].add(sector_byte)
        cards[fingerprint]["responses"][in_h.hex()] += 1

    result = []
    for fp_data in cards.values():
        fp_data["sectors"] = sorted(fp_data["sectors"])
        fp_data["unique_responses"] = len(fp_data["responses"])
        result.append(fp_data)

    result.sort(key=lambda c: -c["count"])
    return result


def analyze_f8(pairs: dict[int, list[tuple[bytes, bytes]]]) -> dict:
    """Analyze F8 bulk data pairs.

    Returns dict with byte5 distribution, IN header clustering, mode analysis.
    """
    f8_pairs = pairs.get(0xF8, [])
    if not f8_pairs:
        return {"count": 0}

    result: dict = {"count": len(f8_pairs)}

    # Byte5 sector distribution
    byte5_out = Counter()
    byte5_in = Counter()
    for out_h, in_h in f8_pairs:
        byte5_out[out_h[5]] += 1
        byte5_in[in_h[5]] += 1

    result["byte5_out_unique"] = len(byte5_out)
    result["byte5_out_full_range"] = len(byte5_out) == 256
    result["byte5_out_top"] = byte5_out.most_common(5)
    result["byte5_in_unique"] = len(byte5_in)
    result["byte5_in_top"] = byte5_in.most_common(3)

    # IN header (bytes 1:7) clustering
    in_headers = Counter()
    for _, in_h in f8_pairs:
        in_headers[in_h[1:7].hex()] += 1

    result["in_header_count"] = len(in_headers)
    result["in_header_top"] = in_headers.most_common(5)

    # Mode analysis: byte1 = 0x78 vs 0x70 vs other
    mode_counts = Counter()
    for out_h, _ in f8_pairs:
        mode_counts[out_h[1]] += 1
    result["modes"] = [{"byte1": hex(k), "count": v} for k, v in mode_counts.most_common()]

    # XOR delta uniqueness
    xor_unique = len(set(compute_xor(out_h, in_h).hex() for out_h, in_h in f8_pairs))
    result["xor_unique"] = xor_unique
    result["xor_all_unique"] = xor_unique == len(f8_pairs)

    return result


def analyze_c9(pairs: dict[int, list[tuple[bytes, bytes]]]) -> dict:
    """Analyze C9 sector ops: ACK count vs data count."""
    c9_pairs = pairs.get(0xC9, [])
    result = {"total": len(c9_pairs), "ack_count": 0, "data_count": 0, "sectors": set()}

    for out_h, in_h in c9_pairs:
        result["sectors"].add(out_h[5])
        if in_h[1:9] == bytes.fromhex("5640494e4b6b3164"):
            result["ack_count"] += 1
        else:
            result["data_count"] += 1

    result["sectors"] = sorted(result["sectors"])
    result["unique_sectors"] = len(result["sectors"])
    return result


def build_text_report(reports: list[tuple[str, bytes]]) -> str:
    """Build the full text analysis report."""
    lines: list[str] = []

    out_count = sum(1 for d, _ in reports if d == "OUT")
    in_count = sum(1 for d, _ in reports if d == "IN")

    lines.append(f"Total HID reports: {len(reports)} (OUT={out_count}, IN={in_count})")
    lines.append("")

    # Pair reports
    pairs = pair_reports(reports)

    # Summary with all commands
    lines.append("Command distribution:")
    for cmd, pair_list in sorted(pairs.items()):
        name = CMD_NAMES.get(cmd, f"0x{cmd:02X}")
        lines.append(f"  0x{cmd:02X} {name:20s}  {len(pair_list):4d} pairs")
    lines.append("")

    # XOR stream analysis
    all_pairs = [(out_h, in_h) for lst in pairs.values() for out_h, in_h in lst]
    results = analyze_xor_stream(all_pairs)

    for cmd, result in sorted(results.items()):
        name = CMD_NAMES.get(cmd, f"0x{cmd:02X}")
        count = result["count"]
        mask = result["repeating_mask"]
        invariant = sum(mask)

        lines.append(
            f"0x{cmd:02X} {name:20s} {count:4d} pairs, {invariant:2d}/{PAYLOAD_SIZE} invariant bytes"
        )

        cmd_pairs = pairs.get(cmd, [])
        if cmd_pairs:
            first_delta = compute_xor(cmd_pairs[0][0], cmd_pairs[0][1])
            lines.append(f"     XOR delta[0]: {first_delta.hex()}")

        if invariant > 0:
            inv_pos = [i for i in range(PAYLOAD_SIZE) if mask[i]]
            lines.append(f"     Invariant:  bytes {inv_pos}")

        if cmd == 0x0D:
            byte5_vals = Counter()
            for out_h, _ in pairs.get(cmd, []):
                byte5_vals[out_h[5]] += 1
            if byte5_vals:
                lines.append(
                    f"     Sector byte5 values: {[hex(v) for v in sorted(byte5_vals)]}"
                )
                lines.append(f"     Unique sectors probed: {len(byte5_vals)}")

    # Multi-card detection
    probe_pairs = pairs.get(0x0D, [])
    if probe_pairs:
        cards = detect_cards(probe_pairs)
        lines.append("")
        lines.append("Card fingerprints (probe IN bytes[4:8]):")
        lines.append(f"  Distinct cards: {len(cards)}")
        for card in cards[:8]:
            lines.append(
                f"    {card['fingerprint']}  probes={card['count']:3d}  "
                f"sectors={len(card['sectors'])}  responses={card['unique_responses']}"
            )
            if len(card["sectors"]) <= 16:
                lines.append(f"      Sectors: {[hex(s) for s in card['sectors']]}")
        if len(cards) > 8:
            lines.append(f"    ... and {len(cards) - 8} more cards")

    # F8 analysis
    if 0xF8 in pairs:
        f8 = analyze_f8(pairs)
        lines.append("")
        lines.append(f"F8 BULK_DATA analysis ({f8['count']} pairs):")
        lines.append(f"  Byte5 OUT unique: {f8['byte5_out_unique']} (full 256 range: {f8['byte5_out_full_range']})")
        lines.append(f"  Byte5 IN  unique: {f8['byte5_in_unique']}")
        if f8.get("byte5_in_top"):
            lines.append(f"  Byte5 IN  top:     {f8['byte5_in_top']}")
        lines.append(f"  IN header variants: {f8['in_header_count']}")
        for hdr, cnt in f8["in_header_top"]:
            lines.append(f"    {hdr}: {cnt}")
        if f8.get("modes"):
            modes_str = " | ".join(
                f"byte1={m['byte1']}={m['count']}x" for m in f8["modes"]
            )
            lines.append(f"  Modes: {modes_str}")
        lines.append(f"  XOR deltas: {f8['xor_unique']} unique / {f8['count']} total (all unique: {f8['xor_all_unique']})")

    # C9 ACK vs data ratio
    if 0xC9 in pairs:
        c9 = analyze_c9(pairs)
        lines.append("")
        lines.append(f"C9 SECTOR_OP: {c9['total']} pairs")
        lines.append(f"  ACK:  {c9['ack_count']}")
        lines.append(f"  Data: {c9['data_count']}")
        lines.append(f"  Sectors: {c9['unique_sectors']} ({[hex(s) for s in c9['sectors'][:16]]}{'...' if len(c9['sectors']) > 16 else ''})")

    return "\n".join(lines)


def build_json_report(reports: list[tuple[str, bytes]]) -> dict:
    """Build a machine-readable JSON report."""
    out_count = sum(1 for d, _ in reports if d == "OUT")
    in_count = sum(1 for d, _ in reports if d == "IN")
    pairs = pair_reports(reports)

    result: dict = {
        "file": "",
        "total_reports": len(reports),
        "out_count": out_count,
        "in_count": in_count,
        "paired_out_in": sum(len(v) for v in pairs.values()),
        "commands": {},
    }

    for cmd, pair_list in sorted(pairs.items()):
        name = CMD_NAMES.get(cmd, f"0x{cmd:02X}")
        cmd_data: dict = {"count": len(pair_list), "name": name}
        if pair_list:
            first = pair_list[0]
            cmd_data["first_xor_delta"] = compute_xor(first[0], first[1]).hex()

        if cmd == 0x0D:
            cards = detect_cards(pair_list)
            cmd_data["cards"] = cards
            byte5_vals = Counter(out_h[5] for out_h, _ in pair_list)
            cmd_data["sectors"] = sorted(byte5_vals.keys())
            cmd_data["unique_sectors"] = len(byte5_vals)

        elif cmd == 0xF8:
            cmd_data["f8"] = analyze_f8(pairs)

        elif cmd == 0xC9:
            cmd_data["c9"] = analyze_c9(pairs)

        result["commands"][name] = cmd_data

    return result


def compare_captures(file1: str, file2: str) -> str:
    """Compare two pcapng files and report differences."""
    lines: list[str] = []

    r1_reports = parse_pcapng(file1)
    r2_reports = parse_pcapng(file2)

    if not r1_reports:
        return f"ERROR: No X100 HID reports in {file1}"
    if not r2_reports:
        return f"ERROR: No X100 HID reports in {file2}"

    p1 = pair_reports(r1_reports)
    p2 = pair_reports(r2_reports)

    all_cmds = sorted(set(p1.keys()) | set(p2.keys()))

    lines.append(f"Capture 1: {len(r1_reports)} reports")
    lines.append(f"Capture 2: {len(r2_reports)} reports")
    lines.append("")

    lines.append("Command comparison:")
    lines.append(f"  {'Command':20s} {'Cap1':>6s} {'Cap2':>6s} {'Delta':>6s}")
    lines.append(f"  {'-'*18:20s} {'-'*6:>6s} {'-'*6:>6s} {'-'*6:>6s}")

    for cmd in all_cmds:
        name = CMD_NAMES.get(cmd, f"0x{cmd:02X}")
        c1 = len(p1.get(cmd, []))
        c2 = len(p2.get(cmd, []))
        delta = c2 - c1
        lines.append(f"  {name:20s} {c1:6d} {c2:6d} {delta:+6d}")

    # XOR delta comparison (are keys different?)
    if 0xD9 in p1 and 0xD9 in p2:
        d1 = compute_xor(p1[0xD9][0][0], p1[0xD9][0][1])
        d2 = compute_xor(p2[0xD9][0][0], p2[0xD9][0][1])
        lines.append("")
        lines.append("Session XOR key comparison (idle pairs):")
        lines.append(f"  Cap1 idle XOR: {d1.hex()}")
        lines.append(f"  Cap2 idle XOR: {d2.hex()}")
        lines.append(f"  Keys match:    {d1.hex() == d2.hex()}")

    # C9 data ratio comparison
    if 0xC9 in p1 or 0xC9 in p2:
        c9a = analyze_c9(p1)
        c9b = analyze_c9(p2)
        lines.append("")
        lines.append("C9 SECTOR_OP data ratio:")
        lines.append(
            f"  Cap1: {c9a['data_count']}/{c9a['total']} data ({c9a['unique_sectors']} sectors)"
        )
        lines.append(
            f"  Cap2: {c9b['data_count']}/{c9b['total']} data ({c9b['unique_sectors']} sectors)"
        )

    # Card comparison
    if 0x0D in p1:
        cards1 = detect_cards(p1[0x0D])
        lines.append("")
        lines.append(f"Cap1 cards: {len(cards1)} distinct")
        for c in cards1[:5]:
            lines.append(f"  {c['fingerprint']}: {c['count']} probes, {len(c['sectors'])} sectors")

    if 0x0D in p2:
        cards2 = detect_cards(p2[0x0D])
        lines.append("")
        lines.append(f"Cap2 cards: {len(cards2)} distinct")
        for c in cards2[:5]:
            lines.append(f"  {c['fingerprint']}: {c['count']} probes, {len(c['sectors'])} sectors")

    # F8 comparison
    if 0xF8 in p1 or 0xF8 in p2:
        f8a = analyze_f8(p1)
        f8b = analyze_f8(p2)
        lines.append("")
        lines.append("F8 BULK_DATA comparison:")
        lines.append(
            f"  Cap1: {f8a['count']} pairs, {f8a['in_header_count']} IN headers, "
            f"byte5 mode: {f8a.get('byte5_out_unique', '?')}"
        )
        lines.append(
            f"  Cap2: {f8b['count']} pairs, {f8b['in_header_count']} IN headers, "
            f"byte5 mode: {f8b.get('byte5_out_unique', '?')}"
        )

    return "\n".join(lines)


def print_analysis(reports: list[tuple[str, bytes]]) -> None:
    """Print structured analysis of a capture."""
    print(build_text_report(reports))


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if sys.argv[1] == "--compare":
        if len(sys.argv) < 4:
            print("Usage: python -m icopykey.cli.analyze_capture --compare <file1> <file2>")
            sys.exit(1)
        print(compare_captures(sys.argv[2], sys.argv[3]))
        sys.exit(0)

    use_json = sys.argv[1] == "--json"
    path = sys.argv[2] if use_json else sys.argv[1]

    reports = parse_pcapng(path)
    if not reports:
        print(f"No X100 HID reports found in {path}")
        sys.exit(1)

    if use_json:
        report = build_json_report(reports)
        report["file"] = path
        print(json.dumps(report, indent=2, default=str))
    else:
        print_analysis(reports)


if __name__ == "__main__":
    main()
