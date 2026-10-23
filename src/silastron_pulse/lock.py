"""Exclusive collection lock. Concurrent runs must not share a state directory."""

from __future__ import annotations

import fcntl
from pathlib import Path
from types import TracebackType

from silastron_pulse.errors import PulseError, ValidationError


class ExclusiveLock:
    def __init__(
        self,
        path: Path,
        *,
        conflict: str,
        error: type[PulseError] = ValidationError,
    ) -> None:
        self.path = path
        self.conflict = conflict
        self.error = error
        self._handle = None

    def __enter__(self) -> "ExclusiveLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise self.error(self.conflict) from exc
        handle.seek(0)
        handle.truncate()
        handle.write("locked\n")
        handle.flush()
        self._handle = handle
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        handle = self._handle
        if handle is None:
            return
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
            self._handle = None


class CollectionLock(ExclusiveLock):
    def __init__(self, path: Path) -> None:
        super().__init__(
            path,
            conflict=f"Another collection run holds {path}; refusing concurrent update",
            error=ValidationError,
        )
