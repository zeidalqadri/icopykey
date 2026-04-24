"""
High level engine for processing MIFARE Classic dumps.

The :class:`DumpEngine` coordinates detection of the appropriate
``FormatStrategy`` for each input file, normalises the raw bytes into a
consistent internal representation (:class:`MifareClassicDump`), and writes
the result to the requested output format.  It optionally integrates
external key recovery tools to fill in missing sector keys, although the
default behaviour simply preserves whatever key data is present in the
input dump.

The engine is designed to process multiple files concurrently using
``ThreadPoolExecutor``.  Consumers of this module should ensure they
maintain ownership of the card dumps being processed—unauthorised
attempts to clone cards may violate local laws and NFC card terms of
service.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Iterable

from concurrent.futures import ThreadPoolExecutor, as_completed

from .format_strategies import get_strategy, FormatStrategy
from .external_tools import run_mfoc  # external integration for key recovery


@dataclass
class MifareClassicDump:
    """Internal representation of a MIFARE Classic card dump.

    Attributes
    ----------
    uid:
        The serial number of the card if known.  Many dump formats embed
        this in a header; otherwise it may be ``None``.
    data:
        The raw memory contents of the card.  For a 1K card this will be
        1024 bytes; for a 4K card 4096 bytes.  Trailer blocks containing
        key A/B and access bits are included.
    keys:
        A list of tuples ``(key_a, key_b)`` for each sector.  Keys are
        represented as 12‑character hexadecimal strings.  If a key is
        unknown the corresponding entry will be ``None`` or the
        placeholder string ``"????????????"``.  The length of ``keys``
        matches the number of sectors in the dump.
    size:
        The total size in bytes of the dump.  This is redundant with
        ``len(data)`` but stored for convenience.
    """

    uid: Optional[str]
    data: bytes
    keys: Optional[List[Tuple[Optional[str], Optional[str]]]] = None
    size: int = 0

    def __post_init__(self) -> None:
        # Derive size from data length if not provided
        if not self.size:
            self.size = len(self.data)

    @property
    def sectors(self) -> int:
        """Return the number of sectors inferred from the data length.

        A 1K card has 16 sectors; each sector is 4 blocks (64 bytes).  A
        4K card has 40 sectors: the first 32 sectors have 4 blocks and the
        remaining 8 have 16 blocks.
        """
        if self.size <= 1024:
            return 16
        # handle 4K and other sizes gracefully
        # 4K = 4096 bytes, 40 sectors; additional larger sizes may map
        # similarly.  Sector count is data length divided by 64 (block
        # size) except for larger sectors; but for our purposes we
        # approximate by 16‑byte block count / blocks per sector.
        # We'll compute number of 16‑byte blocks and divide by 4 for small
        # sectors; large sectors appear last and are 16 blocks each.  We
        # simply compute using NXP spec: 4K card has 32*4 + 8*16 blocks.
        if self.size == 4096:
            return 40
        # fallback: count blocks and divide by 4, rounding down
        return len(self.data) // (4 * 16)

    def to_mfd(self) -> bytes:
        """Return the raw memory contents for writing to an .mfd/.bin file."""
        return self.data

    def to_json_dict(self) -> dict:
        """Return a JSON serialisable dictionary representation of the dump."""
        return {
            "uid": self.uid,
            "size": self.size,
            # base64 encode binary data for JSON transport
            "data": base64.b64encode(self.data).decode("ascii"),
            "keys": self.keys,
        }

    def write(self, out_path: Path, fmt: str) -> None:
        """Write the dump to disk in the given format.

        Parameters
        ----------
        out_path:
            Path to the output file.  The parent directory is created if
            necessary.
        fmt:
            One of ``"mfd"``/``"bin"`` for raw binary, or ``"json"`` for
            JSON with base64 encoded data.  Any other format raises
            ``ValueError``.
        """
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if fmt in {"mfd", "bin"}:
            with open(out_path, "wb") as fh:
                fh.write(self.to_mfd())
        elif fmt == "json":
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(self.to_json_dict(), fh, indent=2)
        else:
            raise ValueError(f"Unsupported format: {fmt}")


class DumpEngine:
    """Engine responsible for processing one or many dump files.

    A ``DumpEngine`` instance may be reused across multiple invocations.
    It lazily loads the available strategies from :mod:`x100_decrypt.strategies`.
    """

    def __init__(self, use_external_recovery: bool = False) -> None:
        """
        Parameters
        ----------
        use_external_recovery:
            If ``True`` the engine will attempt to recover missing keys
            using external tools such as ``mfoc``.  This may increase
            processing time and requires the external binaries to be
            available on the system ``PATH``.  When ``False`` (the
            default) the engine will preserve whatever keys are present
            in the input dump without attempting recovery.
        """
        self.use_external_recovery = use_external_recovery

    def _process_file(self, infile: Path, outdir: Path, fmt: str, strict: bool) -> Tuple[Path, Optional[Exception]]:
        """Internal helper to process a single file.

        Returns a tuple ``(output_path, error)``.  If processing is
        successful ``error`` will be ``None``; otherwise ``output_path``
        will be ``None`` and ``error`` will contain the exception raised.
        """
        try:
            with open(infile, "rb") as fh:
                raw = fh.read()
            strategy: FormatStrategy = get_strategy(raw)
            dump = strategy.normalize(raw, strict=strict)
            # optionally recover missing keys
            if self.use_external_recovery:
                dump = run_mfoc(dump)
            # compute output file name
            out_ext = {
                "mfd": ".mfd",
                "bin": ".bin",
                "json": ".json",
            }.get(fmt)
            if out_ext is None:
                raise ValueError(f"Unknown output format: {fmt}")
            out_path = outdir / f"{infile.stem}{out_ext}"
            dump.write(out_path, fmt)
            return out_path, None
        except Exception as exc:  # pylint: disable=broad-except
            return infile, exc

    def run(self, inputs: Iterable[str], output: str, fmt: str = "bin", *, workers: int = 1, strict: bool = True) -> None:
        """Process one or more input files or directories.

        Parameters
        ----------
        inputs:
            Iterable of file paths or directory paths to process.  If a
            directory is supplied, all files within that directory (recursively)
            will be processed.
        output:
            Directory into which all converted dumps will be written.  The
            directory will be created if it does not exist.
        fmt:
            Output format.  ``"bin"`` and ``"mfd"`` produce raw binary
            dumps; ``"json"`` produces a JSON file with base64 encoded
            data and extracted keys.
        workers:
            Maximum number of worker threads used for concurrent
            processing.  A value of ``1`` disables concurrency.
        strict:
            If ``True`` (default) the engine will abort when encountering
            malformed input files.  When ``False`` it will attempt to
            salvage incomplete dumps by padding/truncating bytes as
            appropriate.  The behaviour ultimately depends on the chosen
            ``FormatStrategy`` implementation.
        """
        outdir = Path(output)
        outdir.mkdir(parents=True, exist_ok=True)
        # Flatten input globs into concrete file paths
        file_list: List[Path] = []
        for item in inputs:
            p = Path(item)
            if p.is_dir():
                for root, _, files in os.walk(p):
                    for name in files:
                        file_list.append(Path(root) / name)
            else:
                file_list.append(p)
        if not file_list:
            raise FileNotFoundError("No input files found.")
        # Process concurrently
        if workers <= 1 or len(file_list) == 1:
            for infile in file_list:
                out_path, err = self._process_file(infile, outdir, fmt, strict)
                if err:
                    raise err
                else:
                    # log progress
                    print(f"Processed {infile} -> {out_path}")
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self._process_file, infile, outdir, fmt, strict): infile
                    for infile in file_list
                }
                for fut in as_completed(futures):
                    infile = futures[fut]
                    out_path, err = fut.result()
                    if err:
                        raise err
                    else:
                        print(f"Processed {infile} -> {out_path}")