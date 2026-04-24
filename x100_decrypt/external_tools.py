"""
External tool integrations for MIFARE Classic key recovery.

This module encapsulates interactions with command line utilities such as
``mfoc`` and ``mfcuk`` which perform on‑card attacks to recover missing
sector keys.  By wrapping these programs in a Python interface we can
handle subprocess errors, timeouts and temporary file management in a
consistent manner.

In environments where the requisite tools are not installed, the wrapper
functions will fall back to a no‑op implementation and simply return the
original dump unchanged.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import MifareClassicDump

def _is_tool_available(name: str) -> bool:
    """Return True if the given executable is available on the PATH."""
    return shutil.which(name) is not None


def run_mfoc(
    dump: 'MifareClassicDump', *, timeout: int = 120, mock: Optional[bool] = None
) -> 'MifareClassicDump':
    """Attempt to recover missing keys via ``mfoc``.

    The `mfoc` tool performs on‑card nested authentication attacks to
    recover sector keys from a physical MIFARE Classic card placed on
    a libnfc‑compatible reader.  It does **not** read from an input
    dump; therefore this function cannot augment the supplied dump
    directly.  Instead, it invokes `mfoc` to produce a fully keyed
    dump file from the reader and then parses that dump.  If the
    process fails or a reader is unavailable, the original dump is
    returned unchanged.

    Parameters
    ----------
    dump: MifareClassicDump
        A baseline dump containing at least the card UID.  If ``uid``
        is ``None`` no attempt will be made.
    timeout: int
        Maximum number of seconds to wait for ``mfoc`` to complete.
    mock: Optional[bool]
        Force mock mode.  When ``True`` the function will skip
        hardware interaction and return the original dump.  When
        ``None`` (default) the value of the ``X100_MFOC_MOCK``
        environment variable is consulted.  Set ``X100_MFOC_MOCK=1``
        during CI or testing to disable reader access.

    Returns
    -------
    MifareClassicDump
        The dump produced by `mfoc` if successful; otherwise the
        original ``dump``.
    """
    # Determine mock mode
    if mock is None:
        env_mock = (os.getenv("X100_MFOC_MOCK", "0") == "1")
        mock = env_mock
    # Skip if mfoc not available or mock mode requested
    if mock or not _is_tool_available("mfoc"):
        return dump
    # Require UID to perform reader attack
    if not dump.uid:
        return dump
    # Prepare to call mfoc; it writes a fully keyed dump to outfile
    with tempfile.TemporaryDirectory() as tmpdir:
        outfile = Path(tmpdir) / "mfoc_output.mfd"
        cmd = [
            "mfoc",
            "-O", str(outfile),
            "-q",
            "-P", "3000",  # limit the number of nested attempts (adjust as needed)
        ]
        try:
            subprocess.run(cmd, check=True, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return dump
        # Read and parse the keyed dump
        try:
            with open(outfile, "rb") as fh:
                keyed = fh.read()
            from .strategies import get_strategy
            strategy = get_strategy(keyed)
            return strategy.normalize(keyed, strict=True)
        except Exception:
            return dump