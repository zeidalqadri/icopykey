"""
High level engine for processing MIFARE Classic dumps.

The :class:`DumpEngine` coordinates detection of the appropriate
``FormatStrategy`` for each input file, normalises the raw bytes into a
consistent internal representation (:class:`MifareClassicDump`), optionally
decrypts encrypted payloads, and writes the result to the requested output
format.  It optionally integrates external key recovery tools to fill in
missing sector keys, although the default behaviour simply preserves
whatever key data is present in the input dump.

The engine is designed to process multiple files concurrently using
``ThreadPoolExecutor``.  Consumers of this module should ensure they
maintain ownership of the card dumps being processed—unauthorised
attempts to clone cards may violate local laws and NFC card terms of
service.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple, Iterable, Dict, Any

from concurrent.futures import ThreadPoolExecutor, as_completed

from .strategies import get_strategy, FormatStrategy
from .external_tools import run_mfoc  # external integration for key recovery
from .crypto import (
    get_decryptor, 
    DecryptionResult, 
    CipherAlgorithm,
    verify_decryption
)
from .keymanager import KeyManager, KeyInfo

logger = logging.getLogger(__name__)


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
    
    The engine now supports optional decryption of encrypted payloads using
    various cryptographic algorithms (AES, DES, 3DES). Keys can be provided
    via hex string, file, environment variable, or derived from a password.
    """

    def __init__(
        self, 
        use_external_recovery: bool = False,
        decryption_key: Optional[bytes] = None,
        decryption_algorithm: Optional[str] = None,
        decryption_iv: Optional[bytes] = None,
        key_manager: Optional[KeyManager] = None,
    ) -> None:
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
        decryption_key:
            Optional decryption key as raw bytes. If provided along with
            decryption_algorithm, encrypted payloads will be decrypted.
        decryption_algorithm:
            Algorithm to use for decryption (e.g., 'aes-128-ecb', 'aes-128-cbc').
            See CipherAlgorithm enum for supported values.
        decryption_iv:
            Initialization vector for CBC mode ciphers. Required if using
            a CBC mode algorithm.
        key_manager:
            Optional KeyManager instance for more advanced key handling.
            If not provided and decryption_key is set, a temporary
            KeyManager will be created internally.
        """
        self.use_external_recovery = use_external_recovery
        self.decryption_key = decryption_key
        self.decryption_algorithm = decryption_algorithm
        self.decryption_iv = decryption_iv
        self.key_manager = key_manager or KeyManager()
        
        # Store decryption statistics
        self._stats: Dict[str, Any] = {
            "files_processed": 0,
            "files_decrypted": 0,
            "decryption_errors": 0,
            "total_time_seconds": 0.0,
        }

    def _decrypt_payload(self, data: bytes) -> DecryptionResult:
        """Attempt to decrypt the given payload.
        
        Parameters
        ----------
        data:
            The encrypted data to decrypt.
            
        Returns
        -------
        DecryptionResult:
            Result containing plaintext or error information.
        """
        if not self.decryption_key or not self.decryption_algorithm:
            # No decryption configured, return data as-is
            return DecryptionResult(
                success=True,
                plaintext=data,
                algorithm="none"
            )
        
        try:
            decryptor = get_decryptor(self.decryption_algorithm)
            result = decryptor.decrypt(data, self.decryption_key, self.decryption_iv)
            
            if result.success:
                # Verify decryption produced valid output
                if verify_decryption(result.plaintext):
                    logger.debug(f"Decryption successful using {self.decryption_algorithm}")
                else:
                    logger.warning("Decryption succeeded but verification failed")
            
            return result
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return DecryptionResult(
                success=False,
                plaintext=b"",
                algorithm=self.decryption_algorithm,
                error_message=str(e)
            )
    
    def _process_file(self, infile: Path, outdir: Path, fmt: str, strict: bool) -> Tuple[Path, Optional[Exception]]:
        """Internal helper to process a single file.

        Returns a tuple ``(output_path, error)``.  If processing is
        successful ``error`` will be ``None``; otherwise ``output_path``
        will be ``None`` and ``error`` will contain the exception raised.
        """
        start_time = time.time()
        
        try:
            with open(infile, "rb") as fh:
                raw = fh.read()
            strategy: FormatStrategy = get_strategy(raw)
            dump = strategy.normalize(raw, strict=strict)
            
            # Optionally decrypt the payload
            if self.decryption_key and self.decryption_algorithm:
                decrypt_result = self._decrypt_payload(dump.data)
                if decrypt_result.success:
                    dump.data = decrypt_result.plaintext
                    dump.size = len(dump.data)
                    self._stats["files_decrypted"] += 1
                else:
                    self._stats["decryption_errors"] += 1
                    if strict:
                        raise ValueError(f"Decryption failed: {decrypt_result.error_message}")
            
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
            
            # Update statistics
            elapsed = time.time() - start_time
            self._stats["files_processed"] += 1
            self._stats["total_time_seconds"] += elapsed
            
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