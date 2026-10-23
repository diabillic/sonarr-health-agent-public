"""Small JSON state file so decisions survive restarts (stall timers, cooldowns)."""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any


class State:
    SECTIONS = ("progress", "first_seen", "notified", "attempts", "escalated")

    def __init__(self, path: str):
        self.path = path
        self.data: dict[str, dict[str, Any]] = {s: {} for s in self.SECTIONS}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    loaded = json.load(fh)
                for s in self.SECTIONS:
                    self.data[s] = loaded.get(s, {})
            except (OSError, ValueError):
                pass  # corrupt state just means timers restart

    def save(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    def __getitem__(self, section: str) -> dict[str, Any]:
        return self.data[section]

    def first_seen(self, key: str, now: float | None = None) -> float:
        """Timestamp when `key` was first observed; records now if new."""
        now = now or time.time()
        return self.data["first_seen"].setdefault(key, now)

    def within(self, section: str, key: str, hours: float, now: float | None = None) -> bool:
        ts = self.data[section].get(key)
        return ts is not None and (now or time.time()) - ts < hours * 3600

    def mark(self, section: str, key: str, now: float | None = None) -> None:
        self.data[section][key] = now or time.time()

    def prune(self, section: str, keep_prefix: str, live: set[str]) -> None:
        """Drop keys under `keep_prefix` whose id is no longer live (e.g. left the queue)."""
        sec = self.data[section]
        for k in list(sec):
            if k.startswith(keep_prefix) and k[len(keep_prefix):].split("|")[0] not in live:
                del sec[k]
