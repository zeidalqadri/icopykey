"""
Logging setup for CopyKEY CLI.

Provides file + console logging with configurable levels and
automatic log directory creation.  Respects the config file's
log_dir setting.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_CONSOLE_FORMAT = "%(levelname)-7s: %(message)s"


def setup_logging(
    verbose: bool = False,
    log_file: str | Path | None = None,
    log_dir: str | Path | None = None,
    console_level: int | None = None,
    file_level: int = logging.DEBUG,
) -> logging.Logger:
    """Configure logging for the CLI application.

    Parameters
    ----------
    verbose : bool
        If True, console log level is DEBUG; otherwise INFO.
    log_file : str or Path, optional
        Explicit path to the log file.
    log_dir : str or Path, optional
        Directory for auto-named log files.
    console_level : int, optional
        Override console log level.
    file_level : int
        Log level for the file handler (default DEBUG).

    Returns
    -------
    logging.Logger
        The root logger for the CLI package (``copykey_cli``).
    """
    root_logger = logging.getLogger("copykey_cli")
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stderr)
    if console_level is None:
        console_level = logging.DEBUG if verbose else logging.INFO
    console.setLevel(console_level)
    console.setFormatter(logging.Formatter(DEFAULT_CONSOLE_FORMAT, DEFAULT_DATE_FORMAT))
    root_logger.addHandler(console)

    # File handler
    if log_file:
        file_path = Path(log_file)
    elif log_dir:
        log_dir_path = Path(log_dir)
        log_dir_path.mkdir(parents=True, exist_ok=True)
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = log_dir_path / f"copykey_cli_{timestamp}.log"
    else:
        file_path = None

    if file_path:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(file_path), encoding="utf-8")
        fh.setLevel(file_level)
        fh.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT, DEFAULT_DATE_FORMAT))
        root_logger.addHandler(fh)
        root_logger.debug("Logging to file: %s", file_path)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the ``copykey_cli`` namespace."""
    return logging.getLogger(f"copykey_cli.{name}")
