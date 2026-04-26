"""
Progress indicators for CopyKEY CLI.

Wraps `rich.progress` when available; falls back to simple
text-based progress output.
"""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from typing import Generator, Iterator

try:
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
        TimeElapsedColumn,
    )
    from rich.live import Live
    from rich.spinner import Spinner

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover (optional dependency)
    RICH_AVAILABLE = False


class ProgressIndicator:
    """Abstract base exposing a common interface for progress."""

    def start(self, total: int, description: str = "") -> None:
        """Begin a progress operation."""

    def update(self, advance: int = 1) -> None:
        """Advance the progress counter."""

    def finish(self) -> None:
        """Mark the operation as complete."""


class RichProgress(ProgressIndicator):
    """Rich-based progress bar."""

    def __init__(self) -> None:
        self._progress: Progress | None = None
        self._task_id: int | None = None

    def start(self, total: int, description: str = "") -> None:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            transient=True,
        )
        self._progress.start()
        self._task_id = self._progress.add_task(description, total=total)

    def update(self, advance: int = 1) -> None:
        if self._progress and self._task_id is not None:
            self._progress.update(self._task_id, advance=advance)

    def finish(self) -> None:
        if self._progress:
            self._progress.stop()
            self._progress = None
            self._task_id = None


class PlainProgress(ProgressIndicator):
    """Simple text-based progress fallback."""

    def __init__(self) -> None:
        self._total = 0
        self._current = 0
        self._desc = ""

    def start(self, total: int, description: str = "") -> None:
        self._total = total
        self._current = 0
        self._desc = description
        if description:
            sys.stderr.write(f"{description}...\n")

    def update(self, advance: int = 1) -> None:
        self._current += advance
        pct = int(self._current / self._total * 100) if self._total else 0
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        sys.stderr.write(f"\r  [{bar}] {pct:3d}%  ({self._current}/{self._total})")
        sys.stderr.flush()

    def finish(self) -> None:
        if self._total:
            sys.stderr.write("\n")
        sys.stderr.flush()


def create_progress() -> ProgressIndicator:
    """Factory: return appropriate progress indicator."""
    if RICH_AVAILABLE:
        return RichProgress()
    return PlainProgress()


class SpinnerIndicator:
    """Animated spinner for indefinite-duration operations."""

    def __init__(self, message: str = "") -> None:
        self._message = message
        self._active = False
        self._start_time = 0.0

    def start(self) -> None:
        """Begin the spinner."""
        self._active = True
        self._start_time = time.time()
        if RICH_AVAILABLE:
            self._console = __import__("rich.console", fromlist=["Console"]).Console()
            self._live = __import__("rich.live", fromlist=["Live"]).Live(
                refresh_per_second=10, transient=True
            )
            self._live.start()
        else:
            sys.stderr.write(f"\r  {self._message} ...")
            sys.stderr.flush()

    def update(self, message: str) -> None:
        """Change the spinner message."""
        self._message = message
        if RICH_AVAILABLE and hasattr(self, '_live'):
            self._live.update(
                __import__("rich.spinner", fromlist=["Spinner"]).Spinner("dots", text=message)
            )
        else:
            sys.stderr.write(f"\r  {message} ...")
            sys.stderr.flush()

    def stop(self) -> None:
        """Stop the spinner."""
        self._active = False
        elapsed = time.time() - self._start_time
        if RICH_AVAILABLE and hasattr(self, '_live'):
            self._live.stop()
        sys.stderr.write(f"\r  {self._message} ... done ({elapsed:.1f}s)\n")
        sys.stderr.flush()


@contextmanager
def spinning(message: str = "Working") -> Generator[SpinnerIndicator, None, None]:
    """Context manager for a spinning indicator.

    Usage::

        with spinning("Decoding sectors") as sp:
            result = do_work()
            sp.update("Processing results")
    """
    si = SpinnerIndicator(message)
    si.start()
    try:
        yield si
    finally:
        si.stop()
