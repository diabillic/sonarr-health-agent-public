"""Import list health, with automatic Trakt token renewal.

Sonarr only renews a Trakt token when `Expires` is within 5 minutes of now. If Trakt
rejects a token before that (revoked, or a shorter real lifetime), Sonarr keeps
failing until someone re-authenticates. We back-date `Expires` and trigger a sync
of that one list, which makes Sonarr run its own renewal against auth.servarr.com
with the stored refresh token. If the refresh token is dead too, a human has to
click "Authenticate with Trakt" once; we say so with a direct link.
"""

from __future__ import annotations

import copy
import logging
import re
from datetime import datetime, timezone

from .config import Config
from .findings import Finding
from .sonarr import Sonarr, field_value, set_field
from .state import State

log = logging.getLogger(__name__)

BACKDATED_EXPIRY = "2000-01-01T00:00:00Z"
HEALTH_SOURCE = "ImportListStatusCheck"


def parse_dt(value: object) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    # .NET emits up to 7 fractional digits; Python accepts at most 6.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def flagged_list_names(health: list[dict], all_names: list[str]) -> set[str]:
    flagged: set[str] = set()
    for item in health:
        if item.get("source") != HEALTH_SOURCE:
            continue
        msg = item.get("message", "")
        if msg.lower().startswith("all "):
            return set(all_names)
        flagged.update(n for n in all_names if n and n in msg)
    return flagged


def check_import_lists(sonarr: Sonarr, state: State, cfg: Config, health: list[dict], now: datetime) -> list[Finding]:
    lists = sonarr.import_lists()
    flagged = flagged_list_names(health, [lst.get("name", "") for lst in lists])
    findings: list[Finding] = []

    for lst in lists:
        name = lst.get("name", f"#{lst.get('id')}")
        if lst.get("implementation", "").startswith("Trakt"):
            f = _check_trakt(sonarr, state, cfg, lst, name in flagged, now)
            if f:
                findings.append(f)
        elif name in flagged:
            findings.append(
                Finding(
                    key=f"importlist:{lst['id']}",
                    summary=f"Import list '{name}' ({lst.get('implementation')}) is failing.",
                    escalate=True,
                    details={"list": name, "implementation": lst.get("implementation")},
                )
            )
    return findings


def _check_trakt(sonarr: Sonarr, state: State, cfg: Config, lst: dict, flagged: bool, now: datetime) -> Finding | None:
    name = lst.get("name")
    key = f"importlist:{lst['id']}"
    reauth = (
        f"Re-authenticate once: {cfg.link_base}/settings/importlists > '{name}' > "
        "Authenticate with Trakt > Save."
    )

    if not field_value(lst, "accessToken") or not field_value(lst, "refreshToken"):
        return Finding(key, f"Trakt list '{name}' has no stored tokens. {reauth}", severity="error")

    expires = parse_dt(field_value(lst, "expires"))
    expired = expires is None or expires <= now
    if not expired and not flagged:
        return None

    if not expired:
        # Flagged by health but token not yet due: confirm it is really an auth/API failure.
        ok, msgs = sonarr.test_import_list(lst)
        if ok:
            return None  # transient; the health warning clears on the next scheduled sync
        log.info("Trakt list %s failed test before expiry: %s", name, msgs)

    if state.within("attempts", key, cfg.trakt_retry_hours, now.timestamp()):
        return Finding(
            key,
            f"Trakt list '{name}' still failing; automatic renewal was already tried in the last "
            f"{cfg.trakt_retry_hours}h. {reauth}",
            severity="error",
        )

    if cfg.dry_run:
        return Finding(
            key,
            f"[dry run] Would force Trakt token renewal for '{name}' (back-date expiry, sync list).",
            severity="info",
            resolved=True,
        )

    state.mark("attempts", key, now.timestamp())
    log.info("Forcing Trakt token renewal for %s", name)
    patched = copy.deepcopy(lst)
    set_field(patched, "expires", BACKDATED_EXPIRY)
    sonarr.update_import_list(patched, force=True)
    cmd = sonarr.command("ImportListSync", definitionId=lst["id"])
    sonarr.wait_command(cmd["id"])

    fresh = sonarr.import_list(lst["id"])
    new_expiry = parse_dt(field_value(fresh, "expires"))
    if new_expiry and new_expiry > now:
        ok, msgs = sonarr.test_import_list(fresh)
        if ok:
            return Finding(key, f"Renewed Trakt token for '{name}'; list test passes.", severity="info", resolved=True)
        return Finding(
            key,
            f"Renewed Trakt token for '{name}' but the list test still fails: {'; '.join(msgs)}",
            severity="error",
            escalate=True,
            details={"list": name, "test_errors": msgs},
        )
    return Finding(key, f"Trakt token renewal failed for '{name}' (refresh token likely revoked). {reauth}", severity="error")
