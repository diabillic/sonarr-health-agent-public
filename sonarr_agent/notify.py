"""Notifications: Discord embeds, or any Apprise URL as markdown (see notice.py)."""

from __future__ import annotations

import logging

from .bus import push_alert
from .findings import Finding
from .notice import Outbox, digest
from .state import State

log = logging.getLogger(__name__)

AUTHOR = "Sonarr agent"


class Notifier:
    def __init__(self, urls: list[str], renotify_hours: int, state: State, dry_run: bool = False,
                 bot_url: str = "", bot_token: str = ""):
        self.renotify_hours = renotify_hours
        self.state = state
        self.dry_run = dry_run  # dry-run "would fix" lines repeat each cycle, so dedupe them too
        self.bot_url, self.bot_token = bot_url, bot_token  # Discord bot first, Apprise as fallback
        self.outbox = Outbox(urls)

    def send(self, findings: list[Finding], diagnosis: str | None = None) -> None:
        """Send one digest per cycle. Fixes always go out; open issues repeat only every renotify_hours."""
        fresh = [
            f for f in findings
            if (f.resolved and not self.dry_run) or not self.state.within("notified", f.key, self.renotify_hours)
        ]
        if not fresh and not diagnosis:
            return

        msg = digest(AUTHOR, fresh, diagnosis=diagnosis,
                     footer="Dry run: nothing is changed" if self.dry_run else "",
                     fixed_heading="🧪 Would fix (dry run)" if self.dry_run else "✅ Fixed")
        body = msg.markdown()
        log.info("%s\n%s", msg.title, body)
        for f in fresh:
            self.state.mark("notified", f.key)
        if self.bot_url and push_alert(self.bot_url, self.bot_token, "sonarr", msg.title, body, fresh, diagnosis):
            return
        self.outbox.send(msg)
