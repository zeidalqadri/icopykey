"""
x100_decrypt package
====================

This package contains tools to normalise, convert and validate MIFARE Classic
card dumps exported by various cloning devices.  The primary goal of the
project is to provide a production‑quality, pluggable architecture for
converting proprietary dump formats (such as those produced by X100/CopyKey
cloners) into standard formats (.mfd or .bin), decrypting encrypted payloads
when encryption is detected, and aiding in the recovery of missing keys via
external tools like ``mfoc`` or ``hardnested``.

The package exposes a handful of modules:

* :mod:`x100_decrypt.engine` – provides the high level ``DumpEngine`` that
  coordinates format detection, normalisation, optional decryption and key recovery.
* :mod:`x100_decrypt.strategies` – contains the pluggable
  ``FormatStrategy`` hierarchy used to interpret different dump
  formats.  The default strategies include
  :class:`~x100_decrypt.strategies.X100FormatStrategy` for the
  X100/CopyKey export format and
  :class:`~x100_decrypt.strategies.RawFormatStrategy` for raw
  MIFARE dumps.
* :mod:`x100_decrypt.crypto` – provides cryptographic primitives for
  decrypting MIFARE Classic data streams, including support for AES-128,
  DES/3DES, and legacy crypto1 stream cipher operations.
* :mod:`x100_decrypt.keymanager` – handles secure key input from multiple
  sources (hex strings, key files, environment variables) with validation
  and key derivation functions.
* :mod:`x100_decrypt.external_tools` – provides thin wrappers around
  card‑dumping and key‑recovery tools such as ``mfoc``.  These wrappers
  encapsulate common subprocess logic and provide timeouts and error
  propagation.
* :mod:`x100_decrypt.cli` – offers a command line interface implemented
  with :mod:`argparse` allowing batch conversion of dumps to various
  output formats, concurrency control and ownership confirmation.

The package is intentionally modular so that new strategies, decryption
algorithms or external tool integrations can be added without altering
the rest of the codebase.

Legal Disclaimer
----------------
MIFARE Classic cards are widely used for access control and ticketing
systems. Cloning or modifying card data without permission may violate
local laws and system terms of service. You should only use this tool
on cards you own or have explicit authorisation to analyse. The authors
assume no liability for misuse of this software.
"""

from .engine import DumpEngine, MifareClassicDump
from .strategies import FormatStrategy  # re‑export for convenience
__all__ = ["DumpEngine", "MifareClassicDump", "FormatStrategy"]