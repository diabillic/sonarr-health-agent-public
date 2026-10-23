"""Queue remediation: blocked imports, stuck failures, stalled downloads.

Queue records are grouped by downloadId, because a season pack shows up as one
record per episode but is a single download to act on.
"""

from __future__ import annotations

import logging
from datetime import datetime

from .config import Config
from .findings import Finding
from .sonarr import Sonarr
from .state import State

log = logging.getLogger(__name__)

STALL_STATUSES = {"downloading", "warning"}

# Permanent rejections that mean the release is simply not wanted, so removing and
# blocklisting it is safe. Anything else (parse/mapping failures) goes to escalation.
DISCARDABLE_REJECTIONS = (
    "not an upgrade",
    "not a custom format upgrade",
    "not a quality revision upgrade",
    "not wanted in profile",
    "sample",
    "already imported",
)


def _messages(rec: dict) -> list[str]:
    out = [f"{m.get('title', '')}: {', '.join(m.get('messages') or [])}".strip(": ") for m in rec.get("statusMessages") or []]
    if rec.get("errorMessage"):
        out.append(rec["errorMessage"])
    return out


class QueueChecker:
    def __init__(self, sonarr: Sonarr, state: State, cfg: Config, health: list[dict], now: datetime):
        self.sonarr, self.state, self.cfg, self.health = sonarr, state, cfg, health
        self.now = now.timestamp()
        self.refresh_sent = False

    def run(self) -> list[Finding]:
        groups: dict[str, list[dict]] = {}
        for rec in self.sonarr.queue():
            groups.setdefault(rec.get("downloadId") or f"queue-{rec['id']}", []).append(rec)

        live = set(groups)
        self.state.prune("progress", "", live)
        self.state.prune("first_seen", "dl:", live)
        self.state.prune("attempts", "dl:", live)

        findings: list[Finding] = []
        stalled: list[tuple[str, dict]] = []
        for dl_id, recs in groups.items():
            rec = recs[0]
            tstate = rec.get("trackedDownloadState")
            if tstate == "importBlocked":
                findings.append(self._blocked(dl_id, rec))
            elif tstate in ("importPending", "importing"):
                f = self._pending(dl_id, rec, tstate)
                if f:
                    findings.append(f)
            elif tstate == "failedPending":
                f = self._failed_pending(dl_id, rec)
                if f:
                    findings.append(f)
            elif rec.get("status") in STALL_STATUSES and self._is_stalled(dl_id, rec):
                stalled.append((dl_id, rec))
            elif rec.get("status") == "downloadClientUnavailable":
                pass  # reported via health (DownloadClientStatusCheck)

        findings.extend(self._handle_stalled(stalled))
        return findings

    # --- import blocked ---

    def _blocked(self, dl_id: str, rec: dict) -> Finding:
        title = rec.get("title", dl_id)
        key = f"dl:{dl_id}"
        msgs = _messages(rec)
        attempt_key = f"dl:{dl_id}|import"
        if attempt_key in self.state["attempts"]:
            return Finding(
                key, f"'{title}' is still import-blocked after an automatic import attempt.",
                escalate=True, details={"downloadId": dl_id, "queueId": rec["id"], "messages": msgs},
            )

        candidates = self.sonarr.manual_import_candidates(dl_id)
        if not candidates:
            return Finding(
                key,
                f"'{title}' is import-blocked and Sonarr sees no importable files "
                "(often a remote path mapping or permissions problem).",
                escalate=True,
                details={"downloadId": dl_id, "queueId": rec["id"], "outputPath": rec.get("outputPath"), "messages": msgs},
            )

        importable = [c for c in candidates if c.get("series") and c.get("episodes") and not c.get("rejections")]
        rejected = [c for c in candidates if c.get("rejections")]

        if importable:
            note = f" ({len(rejected)} rejected file(s) left behind)" if rejected else ""
            if self.cfg.dry_run:
                return Finding(key, f"[dry run] Would manually import {len(importable)} file(s) for '{title}'{note}.", "info", resolved=True)
            self.sonarr.manual_import([_import_file(c, dl_id) for c in importable])
            self.state.mark("attempts", attempt_key, self.now)
            return Finding(key, f"Triggered manual import of {len(importable)} file(s) for '{title}'{note}.", "info", resolved=True)

        reasons = sorted({r.get("reason", "") for c in rejected for r in c["rejections"]})
        discardable = (
            len(rejected) == len(candidates)
            and all(r.get("type") == "permanent" for c in rejected for r in c["rejections"])
            and all(any(d in reason.lower() for d in DISCARDABLE_REJECTIONS) for reason in reasons)
        )
        if discardable and self.cfg.remove_rejected:
            return self._remove(dl_id, rec, blocklist=True, redownload=False, why=f"every file rejected ({'; '.join(reasons)})")

        return Finding(
            key, f"'{title}' is import-blocked and needs a decision: {'; '.join(reasons) or '; '.join(msgs)}",
            escalate=True,
            details={
                "downloadId": dl_id,
                "queueId": rec["id"],
                "messages": msgs,
                "candidates": [
                    {
                        "path": c.get("relativePath") or c.get("path"),
                        "series": (c.get("series") or {}).get("title"),
                        "episodes": len(c.get("episodes") or []),
                        "rejections": c.get("rejections"),
                    }
                    for c in candidates[:20]
                ],
            },
        )

    # --- import pending / importing ---

    def _pending(self, dl_id: str, rec: dict, tstate: str) -> Finding | None:
        age_min = (self.now - self.state.first_seen(f"dl:{dl_id}|{tstate}", self.now)) / 60
        if age_min < self.cfg.import_pending_minutes:
            return None
        title = rec.get("title", dl_id)
        nudge_key = f"dl:{dl_id}|nudge"
        if nudge_key not in self.state["attempts"]:
            self.state.mark("attempts", nudge_key, self.now)
            if not self.cfg.dry_run and not self.refresh_sent:
                self.sonarr.command("RefreshMonitoredDownloads")
                self.refresh_sent = True
            prefix = "[dry run] Would refresh" if self.cfg.dry_run else "Refreshed"
            return Finding(f"dl:{dl_id}", f"{prefix} monitored downloads: '{title}' has been {tstate} for {age_min:.0f} min.", "info", resolved=True)
        if age_min >= 3 * self.cfg.import_pending_minutes:
            return Finding(
                f"dl:{dl_id}", f"'{title}' has been {tstate} for {age_min:.0f} min despite a refresh.",
                escalate=True, details={"downloadId": dl_id, "queueId": rec["id"], "messages": _messages(rec)},
            )
        return None

    # --- failed pending ---

    def _failed_pending(self, dl_id: str, rec: dict) -> Finding | None:
        age_min = (self.now - self.state.first_seen(f"dl:{dl_id}|failedPending", self.now)) / 60
        if age_min < self.cfg.failed_pending_minutes:
            return None
        return self._remove(dl_id, rec, blocklist=True, redownload=True, why=f"failed in download client ({'; '.join(_messages(rec)) or 'no detail'})")

    # --- stalled downloads ---

    def _is_stalled(self, dl_id: str, rec: dict) -> bool:
        sizeleft = rec.get("sizeleft") or 0
        prog = self.state["progress"].get(dl_id)
        if prog is None or sizeleft < prog["sizeleft"]:
            self.state["progress"][dl_id] = {"sizeleft": sizeleft, "since": self.now}
            return False
        return (self.now - prog["since"]) / 60 >= self.cfg.stall_minutes

    def _handle_stalled(self, stalled: list[tuple[str, dict]]) -> list[Finding]:
        if not stalled:
            return []
        client_trouble = [
            h for h in self.health
            if h.get("source", "").startswith("DownloadClient") and h.get("type") in ("warning", "error")
        ]
        if len(stalled) >= self.cfg.mass_stall_threshold or client_trouble:
            # Many stalls at once means SABnzbd itself is paused/broken; blocklisting would destroy good releases.
            return [Finding(
                "queue:mass-stall",
                f"{len(stalled)} download(s) have made no progress for {self.cfg.stall_minutes}+ min. "
                "Looks like a download client problem (SABnzbd paused, disk full, news server down), "
                "so nothing was blocklisted.",
                severity="error",
                escalate=True,
                details={"titles": [r.get("title") for _, r in stalled][:20], "client_health": client_trouble},
            )]
        return [
            self._remove(dl_id, rec, blocklist=True, redownload=True, why=f"no progress for {self.cfg.stall_minutes}+ min")
            for dl_id, rec in stalled
        ]

    # --- shared ---

    def _remove(self, dl_id: str, rec: dict, *, blocklist: bool, redownload: bool, why: str) -> Finding:
        title = rec.get("title", dl_id)
        verb = "blocklisted and re-searched" if redownload else ("removed and blocklisted" if blocklist else "removed")
        if self.cfg.dry_run:
            return Finding(f"dl:{dl_id}", f"[dry run] '{title}' would be {verb}: {why}.", "info", resolved=True)
        self.sonarr.remove_queue_item(rec["id"], remove_from_client=True, blocklist=blocklist, skip_redownload=not redownload)
        self.state["progress"].pop(dl_id, None)
        return Finding(f"dl:{dl_id}", f"'{title}' {verb}: {why}.", "info", resolved=True)


def _import_file(c: dict, dl_id: str) -> dict:
    return {
        "path": c["path"],
        "folderName": c.get("folderName"),
        "seriesId": c["series"]["id"],
        "episodeIds": [e["id"] for e in c["episodes"]],
        "episodeFileId": c.get("episodeFileId"),
        "quality": c.get("quality"),
        "languages": c.get("languages"),
        "releaseGroup": c.get("releaseGroup"),
        "indexerFlags": c.get("indexerFlags", 0),
        "releaseType": c.get("releaseType", "unknown"),
        "downloadId": c.get("downloadId") or dl_id,
    }


def check_queue(sonarr: Sonarr, state: State, cfg: Config, health: list[dict], now: datetime) -> list[Finding]:
    return QueueChecker(sonarr, state, cfg, health, now).run()
