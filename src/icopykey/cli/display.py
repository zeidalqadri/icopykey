"""
Terminal display helpers for CopyKEY CLI.

Uses the `rich` library when available for tables, color, and
styled output.  Falls back to plain-text formatting when `rich`
is not installed.
"""

from __future__ import annotations

import sys
from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.style import Style
    from rich.panel import Panel
    from rich import box

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover (optional dependency)
    RICH_AVAILABLE = False

_console: Any = None


def _get_console() -> Any:
    """Lazy-initialize the rich Console (or a stub)."""
    global _console
    if _console is None:
        if RICH_AVAILABLE:
            _console = Console(highlight=False)
        else:
            _console = _PlainConsole()
    return _console


class _PlainConsole:
    """Minimal console stub when rich is unavailable."""

    @staticmethod
    def print(*args: Any, **kwargs: Any) -> None:
        print(*args, **kwargs)

    @staticmethod
    def rule(title: str = "", **_: Any) -> None:
        if title:
            print(f"\n{'=' * 60}")
            print(f"  {title}")
            print(f"{'=' * 60}")
        else:
            print("=" * 60)


# ── Color constants ──────────────────────────────────────────────

class Color:
    """ANSI / Rich color codes and styles.

    When `rich` is available these map to rich Style objects.
    When not, they emit raw ANSI escape sequences.
    """

    if RICH_AVAILABLE:
        SUCCESS = Style(color="green", bold=True)
        ERROR = Style(color="red", bold=True)
        WARNING = Style(color="yellow", bold=True)
        INFO = Style(color="cyan")
        HEADER = Style(color="bright_blue", bold=True)
        DIM = Style(color="grey50")
        KEY = Style(color="bright_green")
        UID = Style(color="bright_yellow")
        CARD_TYPE = Style(color="magenta")
        DEVICE = Style(color="bright_cyan")
    else:
        _ESC = "\033["
        _RST = _ESC + "0m"
        SUCCESS = _ESC + "32;1m"  # green bold
        ERROR = _ESC + "31;1m"  # red bold
        WARNING = _ESC + "33;1m"  # yellow bold
        INFO = _ESC + "36m"  # cyan
        HEADER = _ESC + "94;1m"  # bright blue bold
        DIM = _ESC + "90m"  # grey
        KEY = _ESC + "92m"  # bright green
        UID = _ESC + "93m"  # bright yellow
        CARD_TYPE = _ESC + "35m"  # magenta
        DEVICE = _ESC + "96m"  # bright cyan


# ── Public display functions ─────────────────────────────────────


def print_success(message: str) -> None:
    """Print a success message (green)."""
    con = _get_console()
    if RICH_AVAILABLE:
        con.print(f"✓ {message}", style=Color.SUCCESS)
    else:
        con.print(f"{Color.SUCCESS}✓ {message}{Color._RST if hasattr(Color, '_RST') else ''}")


def print_error(message: str) -> None:
    """Print an error message (red)."""
    con = _get_console()
    if RICH_AVAILABLE:
        con.print(f"✗ {message}", style=Color.ERROR)
    else:
        con.print(f"{Color.ERROR}✗ {message}{Color._RST if hasattr(Color, '_RST') else ''}")


def print_warning(message: str) -> None:
    """Print a warning message (yellow)."""
    con = _get_console()
    if RICH_AVAILABLE:
        con.print(f"! {message}", style=Color.WARNING)
    else:
        con.print(f"{Color.WARNING}! {message}{Color._RST if hasattr(Color, '_RST') else ''}")


def print_info(message: str) -> None:
    """Print an informational message (cyan)."""
    con = _get_console()
    if RICH_AVAILABLE:
        con.print(message, style=Color.INFO)
    else:
        con.print(f"{Color.INFO}{message}{Color._RST if hasattr(Color, '_RST') else ''}")


def print_header(title: str, subtitle: str = "") -> None:
    """Print an application header panel."""
    con = _get_console()
    if RICH_AVAILABLE:
        if subtitle:
            text = Text.assemble((title, "bold bright_blue"), "\n", (subtitle, "dim"))
        else:
            text = Text(title, style="bold bright_blue")
        panel = Panel(text, box=box.DOUBLE, border_style="bright_blue")
        con.print(panel)
    else:
        print(f"\n{'═' * 60}")
        print(f"  {title}")
        if subtitle:
            print(f"  {subtitle}")
        print(f"{'═' * 60}")


def print_divider(title: str = "") -> None:
    """Print a horizontal divider with optional title."""
    con = _get_console()
    if RICH_AVAILABLE:
        con.rule(title) if title else con.rule()
    else:
        if title:
            print(f"\n{'─' * 60}")
            print(f"  {title}")
            print(f"{'─' * 60}")
        else:
            print(f"{'─' * 60}")


def print_status_line(device_status: str, library_status: str) -> None:
    """Print the device and library status line."""
    con = _get_console()
    if RICH_AVAILABLE:
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        table.add_column(style="bright_cyan")
        table.add_column(style="dim")
        table.add_row("Device:", device_status)
        table.add_row("Library:", library_status)
        con.print(table)
    else:
        print(f"\n  Device:  {device_status}")
        print(f"  Library: {library_status}")


def print_table(headers: list[str], rows: list[list[str]], title: str = "") -> None:
    """Print a formatted table."""
    con = _get_console()
    if RICH_AVAILABLE:
        table = Table(title=title, box=box.ROUNDED)
        for h in headers:
            table.add_column(h, style="bold")
        for row in rows:
            table.add_row(*row)
        con.print(table)
    else:
        if title:
            print(f"\n  {title}")
        col_widths = [max(len(str(c)) for c in col) for col in zip(*([headers] + rows))]
        fmt = "  " + " │ ".join(f"{{:<{w}}}" for w in col_widths)
        print(fmt.format(*headers))
        print("  " + "─┼─".join("─" * w for w in col_widths))
        for row in rows:
            print(fmt.format(*[str(c) for c in row]))


def print_card_info(uid: str, sak: int, atqa: str, card_type: str) -> None:
    """Print card information in a formatted block."""
    if RICH_AVAILABLE:
        con = _get_console()
        text = Text()
        text.append("Card Detected\n", style="bold green")
        text.append(f"  UID:  ", style="dim")
        text.append(f"{uid}\n", style="bright_yellow")
        text.append(f"  SAK:  ", style="dim")
        text.append(f"0x{sak:02X}\n")
        text.append(f"  ATQA: ", style="dim")
        text.append(f"{atqa}\n")
        text.append(f"  Type: ", style="dim")
        text.append(f"{card_type}", style="magenta")
        con.print(Panel(text, box=box.ROUNDED, border_style="green"))
    else:
        print(f"\n  Card Detected:")
        print(f"    UID:  {uid}")
        print(f"    SAK:  0x{sak:02X}")
        print(f"    ATQA: {atqa}")
        print(f"    Type: {card_type}")


def print_key_value(key: str, value: str, indent: int = 2) -> None:
    """Print a single key-value pair."""
    prefix = " " * indent
    con = _get_console()
    if RICH_AVAILABLE:
        text = Text.assemble((f"{prefix}{key}: ", "dim"), (value,))
        con.print(text)
    else:
        print(f"{prefix}{key}: {value}")


def strip_colors(text: str) -> str:
    """Remove ANSI escape sequences (for log files)."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)
