"""Rich console helpers.

A single module owns console creation so ``--no-color`` and non-TTY output are
handled in exactly one place, and so tests can silence everything.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.theme import Theme

__all__ = [
    "error_console",
    "get_console",
    "set_color_enabled",
    "table",
]

_THEME = Theme(
    {"ok": "green", "warn": "yellow", "err": "bold red", "dim": "dim", "hl": "cyan"},
)

_console: Console | None = None
_error_console: Console | None = None


def set_color_enabled(enabled: bool) -> None:
    """(Re)create both consoles with or without colour."""
    global _console, _error_console
    _console = Console(theme=_THEME, no_color=not enabled, highlight=False)
    _error_console = Console(stderr=True, theme=_THEME, no_color=not enabled, highlight=False)


def get_console() -> Console:
    """The stdout console, created on first use."""
    global _console
    if _console is None:
        set_color_enabled(True)
    assert _console is not None
    return _console


def error_console() -> Console:
    """The stderr console, created on first use."""
    global _error_console
    if _error_console is None:
        set_color_enabled(True)
    assert _error_console is not None
    return _error_console


def table(title: str, *headers: str) -> Table:
    """Build a Rich table with the project's standard styling."""
    tbl = Table(title=title, header_style="bold", title_style="bold", pad_edge=False)
    for header in headers:
        tbl.add_column(header)
    return tbl
