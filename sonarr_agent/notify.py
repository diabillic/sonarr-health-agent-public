"""Notifications via Apprise (Discord, Pushover, ntfy, Telegram, email, ... by URL)."""

from __future__ import annotations

import logging

import apprise

from .findings import Finding
from .state import State

log = logging.getLogger(__name__)

ICON = {"info": "✅", "warning": "⚠️", "error": "❌"}


class Notifier:
    def __init__(self, urls: list[str], renotify_hours: int, state: State, dry_run: bool = False):
        self.renotify_hours = renotify_hours
        self.state = state
        self.dry_run = dry_run  # dry-run "would fix" lines repeat each cycle, so dedupe them too
        self.apobj = apprise.Apprise()
        for url in urls:
            if not self.apobj.add(url):
                log.warning("Ignoring invalid notification URL (scheme %s)", url.split(":", 1)[0])

    def send(self, findings: list[Finding], diagnosis: str | None = None) -> None:
        """Send one digest per cycle. Fixes always go out; open issues repeat only every renotify_hours."""
        fresh = [
            f for f in findings
            if (f.resolved and not self.dry_run) or not self.state.within("notified", f.key, self.renotify_hours)
        ]
        if not fresh and not diagnosis:
            return

        fixed = [f for f in fresh if f.resolved]
        open_ = [f for f in fresh if not f.resolved]
        lines = [f"{ICON.get(f.severity, '•')} {f.summary}" for f in fixed + open_]
        if diagnosis:
            lines += ["", "🧠 Diagnosis:", diagnosis]
        title = f"Sonarr agent: {len(fixed)} fixed, {len(open_)} need attention"
        body = "\n".join(lines)

        log.info("%s\n%s", title, body)
        for f in fresh:
            self.state.mark("notified", f.key)
        if len(self.apobj):
            if not self.apobj.notify(title=title, body=body):
                log.warning("One or more notification targets failed")
