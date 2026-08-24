"""Monotonic nonce allocation, persisted across restarts.

The server requires a nonce strictly greater than the last one that key used *in that room*. Two
consequences that bite in practice:

* A process that keeps its counter only in memory starts again at a low value after a restart and
  is refused until it climbs back past its own history.
* Two processes signing with the same key against the same room will interleave and refuse each
  other. One signer per key. This module does not make a key safe to share.

A millisecond clock is used as the floor so a restart is already past anything a previous run
allocated, with a stored counter to break ties inside the same millisecond.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path


class NonceStore:
    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        if self.path and self.path.exists():
            try:
                self._counters = {k: int(v) for k, v in json.loads(self.path.read_text()).items()}
            except (ValueError, OSError):
                # A corrupt store must not wedge the client: the clock floor below still
                # produces a value past any plausible previous run.
                self._counters = {}

    def next(self, scope: str) -> int:
        """Allocate the next nonce for *scope*, typically a room or ``<ns>/<key>``."""
        with self._lock:
            value = max(int(time.time() * 1000), self._counters.get(scope, 0) + 1)
            self._counters[scope] = value
            self._persist()
            return value

    def _persist(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(self._counters, fh)
            os.replace(tmp, self.path)  # atomic, so a crash mid-write cannot truncate the store
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
