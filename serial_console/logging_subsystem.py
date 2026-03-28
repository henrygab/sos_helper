"""
Flexible TX / RX logging subsystem with pluggable handlers.

Design decisions
~~~~~~~~~~~~~~~~
* **Handler protocol** — any object with ``handle(entry)`` and ``close()`` can
  be a handler.  Three concrete implementations are provided: file, in‑memory
  ring buffer, and user callback.
* **Direction filtering** — each handler can optionally restrict itself to TX,
  RX, or both.  This makes it trivial to set up separate TX / RX log files or
  a single unified timeline.
* The **LogManager** is the single coordination point: the serial manager
  pushes raw ``bytes`` into ``log_tx`` / ``log_rx`` and the manager creates a
  timestamped :class:`LogEntry` and fans it out.
* Plain‑text only.  No rotation, compression, or replay.
"""

from __future__ import annotations

import time
from collections import deque
from enum import Enum
from pathlib import Path
from typing import Callable, Deque, List, Optional, Protocol, Set, Union


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Direction(Enum):
    """Data‑flow direction for a log entry."""
    TX = "TX"
    RX = "RX"


class LogEntry:
    """A single timestamped log record."""

    __slots__ = ("timestamp", "direction", "data")

    def __init__(self, timestamp: float, direction: Direction, data: bytes) -> None:
        self.timestamp = timestamp
        self.direction = direction
        self.data = data

    @property
    def text(self) -> str:
        """Decode the payload as ASCII (replacing non‑printable bytes)."""
        return self.data.decode(encoding="latin-1", errors="ignore")

    def format(self, include_direction: bool = True) -> str:
        """Human‑readable single‑line representation."""
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        frac = f"{self.timestamp % 1:.3f}"[1:]  # → ".NNN"
        prefix = f"[{ts}{frac}]"
        if include_direction:
            prefix += f" {self.direction.value}"
        # Represent the payload on one line (replace newlines with a visible
        # marker so that each LogEntry stays on exactly one output line).
        sanitised = self.text.replace("\r", "").replace("\n", "↵")
        return f"{prefix} {sanitised}"


# ---------------------------------------------------------------------------
# Handler protocol and implementations
# ---------------------------------------------------------------------------

class LogHandler(Protocol):
    """Structural typing protocol for log handlers."""

    def handle(self, entry: LogEntry) -> None: ...
    def close(self) -> None: ...


class FileLogHandler:
    """Append log entries to a plain‑text file.

    Parameters
    ----------
    path:
        File path to write to (created / appended).
    directions:
        If given, only entries matching these directions are written.
        ``None`` means *both* TX and RX (unified log).
    """

    def __init__(
        self,
        path: Union[str, Path],
        directions: Optional[Set[Direction]] = None,
    ) -> None:
        self._path = Path(path)
        self._directions = directions
        self._file = open(self._path, "a", encoding="utf-8")  # noqa: SIM115

    def handle(self, entry: LogEntry) -> None:
        if self._directions is not None and entry.direction not in self._directions:
            return
        include_dir = self._directions is None  # unified → show direction tag
        self._file.write(entry.format(include_direction=include_dir) + "\n")
        self._file.flush()

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    def __repr__(self) -> str:
        dirs = "TX+RX" if self._directions is None else "+".join(
            d.value for d in sorted(self._directions, key=lambda d: d.value)
        )
        return f"FileLogHandler({self._path!s}, {dirs})"


class MemoryLogHandler:
    """Store log entries in an in‑memory ring buffer.

    Useful for programmatic inspection (e.g. from a command that wants to
    review recent traffic) without touching the filesystem.
    """

    def __init__(
        self,
        max_entries: int = 10_000,
        directions: Optional[Set[Direction]] = None,
    ) -> None:
        self._buffer: Deque[LogEntry] = deque(maxlen=max_entries)
        self._directions = directions

    def handle(self, entry: LogEntry) -> None:
        if self._directions is not None and entry.direction not in self._directions:
            return
        self._buffer.append(entry)

    def close(self) -> None:
        pass  # nothing to release

    @property
    def entries(self) -> List[LogEntry]:
        """Snapshot of buffered entries (oldest first)."""
        return list(self._buffer)

    def clear(self) -> None:
        self._buffer.clear()

    def __repr__(self) -> str:
        return f"MemoryLogHandler({len(self._buffer)} entries)"


class CallbackLogHandler:
    """Forward every log entry to a caller‑provided function.

    The callback signature is ``callback(entry: LogEntry) -> None``.
    """

    def __init__(
        self,
        callback: Callable[[LogEntry], None],
        directions: Optional[Set[Direction]] = None,
    ) -> None:
        self._callback = callback
        self._directions = directions

    def handle(self, entry: LogEntry) -> None:
        if self._directions is not None and entry.direction not in self._directions:
            return
        self._callback(entry)

    def close(self) -> None:
        pass

    def __repr__(self) -> str:
        return f"CallbackLogHandler({self._callback!r})"


# ---------------------------------------------------------------------------
# LogManager — central coordinator
# ---------------------------------------------------------------------------

class LogManager:
    """Fan‑out coordinator: receives raw TX / RX bytes and dispatches
    :class:`LogEntry` objects to every registered handler."""

    def __init__(self) -> None:
        self._handlers: List[LogHandler] = []

    # -- handler management --------------------------------------------------

    def add_handler(self, handler: LogHandler) -> None:
        self._handlers.append(handler)

    def remove_handler(self, handler: LogHandler) -> None:
        self._handlers.remove(handler)

    @property
    def handlers(self) -> List[LogHandler]:
        """Read‑only view of currently registered handlers."""
        return list(self._handlers)

    # -- logging entry points ------------------------------------------------

    def log_rx(self, data: bytes) -> None:
        """Create an RX entry and dispatch to all handlers."""
        self._dispatch(LogEntry(time.time(), Direction.RX, data))

    def log_tx(self, data: bytes) -> None:
        """Create a TX entry and dispatch to all handlers."""
        self._dispatch(LogEntry(time.time(), Direction.TX, data))

    # -- teardown ------------------------------------------------------------

    def close(self) -> None:
        """Close and remove all handlers."""
        for handler in self._handlers:
            try:
                handler.close()
            except Exception:
                pass
        self._handlers.clear()

    # -- internal ------------------------------------------------------------

    def _dispatch(self, entry: LogEntry) -> None:
        for handler in self._handlers:
            try:
                handler.handle(entry)
            except Exception:
                pass  # Never let a handler error propagate upward.
