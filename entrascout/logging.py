"""Configurable logging — console (rich) + file + JSONL history."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler


_console = Console(stderr=True)


class HistoryWriter:
    """Per-run history file. Every HTTP/DNS probe is logged here."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self.path.open("a", encoding="utf-8")

    def emit(self, record: dict[str, Any]) -> None:
        record.setdefault("ts", datetime.now(timezone.utc).isoformat())
        try:
            self._fp.write(json.dumps(record, default=str))
            self._fp.write("\n")
            self._fp.flush()
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        try:
            self._fp.close()
        except Exception:  # noqa: BLE001
            pass


def configure(
    *,
    log_dir: Path,
    level: str = "DEBUG",
    log_file: str = "entrascout.log",
    rich_console: bool = True,
    history_filename: str = "history.jsonl",
) -> tuple[logging.Logger, HistoryWriter]:
    """Configure global root logger. Returns (logger, history_writer).

    The file handler ALWAYS records DEBUG (full audit trail).
    The console handler respects the requested level for human readability.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file_path = log_dir / log_file

    root = logging.getLogger("entrascout")
    # Root level is the most permissive — handlers do their own filtering
    root.setLevel(logging.DEBUG)
    root.propagate = False

    # Clear existing handlers
    for h in list(root.handlers):
        root.removeHandler(h)

    # File handler — ALWAYS DEBUG, no exceptions
    fh = logging.FileHandler(log_file_path, mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    root.addHandler(fh)

    # Console handler — respects user-supplied level
    console_level = getattr(logging, level.upper(), logging.INFO)
    if rich_console:
        ch = RichHandler(
            console=_console,
            show_time=True,
            show_path=False,
            markup=False,
            rich_tracebacks=True,
            level=console_level,
        )
    else:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(console_level)
        ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root.addHandler(ch)

    history = HistoryWriter(log_dir / history_filename)
    return root, history


def reattach_to_dir(log_dir: Path, history_filename: str = "history.jsonl") -> HistoryWriter:
    """Move file handler + history into a different dir (used after run dir is created)."""
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("entrascout")
    # Remove previous FileHandler(s)
    for h in list(root.handlers):
        if isinstance(h, logging.FileHandler):
            h.close()
            root.removeHandler(h)
    log_file_path = log_dir / "entrascout.log"
    fh = logging.FileHandler(log_file_path, mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    root.addHandler(fh)
    return HistoryWriter(log_dir / history_filename)


def get_logger(name: str = "entrascout") -> logging.Logger:
    return logging.getLogger(name)
