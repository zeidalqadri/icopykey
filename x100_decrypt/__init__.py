"""
x100_decrypt package
====================

This package contains tools to normalise, convert and validate MIFARE Classic
card dumps exported by various cloning devices.  The primary goal of the
project is to provide a production‑quality, pluggable architecture for
converting proprietary dump formats (such as those produced by X100/CopyKey
cloners) into standard formats (.mfd or .bin) and to aid in the recovery of
missing keys via external tools like ``mfoc`` or ``hardnested``.

The package exposes a handful of modules:

* :mod:`x100_decrypt.engine` – provides the high level ``DumpEngine`` that
  coordinates format detection, normalisation and optional key recovery.
* :mod:`x100_decrypt.format_strategies` – contains the pluggable
  ``FormatStrategy`` hierarchy used to interpret different dump
  formats.  The default strategies include
  :class:`~x100_decrypt.format_strategies.X100FormatStrategy` for the
  X100/CopyKey export format and
  :class:`~x100_decrypt.format_strategies.RawFormatStrategy` for raw
  MIFARE dumps.
* :mod:`x100_decrypt.external_tools` – provides thin wrappers around
  card‑dumping and key‑recovery tools such as ``mfoc``.  These wrappers
  encapsulate common subprocess logic and provide timeouts and error
  propagation.
* :mod:`x100_decrypt.cli` – offers a command line interface implemented
  with :mod:`argparse` allowing batch conversion of dumps to various
  output formats, concurrency control and ownership confirmation.

The package is intentionally modular so that new strategies or external
tool integrations can be added without altering the rest of the codebase.
"""

from .engine import DumpEngine, MifareClassicDump
from .format_strategies import FormatStrategy  # re‑export for convenience
__all__ = ["DumpEngine", "MifareClassicDump", "FormatStrategy"]