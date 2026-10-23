"""Entry point: python -m sonarr_agent [--once]"""

from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime, timezone

import requests

from .config import Config
from .escalate import escalate
from .findings import Finding
from .importlists import HEALTH_SOURCE, check_import_lists
from .notify import Notifier
from .queue import check_queue
from .sonarr import Sonarr, SonarrError
from .state import State

log = logging.getLogger("sonarr_agent")

# Health sources whose problems the checks above already own.
HANDLED_SOURCES = {HEALTH_SOURCE}


def health_findings(health: list[dict], cfg: Config) -> list[Finding]:
    out = []
    for h in health:
        source = h.get("source", "")
        if h.get("type") not in ("warning", "error") or source in HANDLED_SOURCES or source in cfg.health_ignore:
            continue
        out.append(Finding(
            key=f"health:{source}:{h.get('message', '')[:80]}",
            summary=f"Health {h['type']}: {h.get('message')}",
            severity=h["type"],
            escalate=True,
            details={"source": source, "wiki": h.get("wikiUrl")},
        ))
    return out


def run_cycle(cfg: Config, sonarr: Sonarr, state: State, notifier: Notifier) -> list[Finding]:
    now = datetime.now(timezone.utc)
    try:
        sonarr.status()
        health = sonarr.health()
    except (requests.RequestException, SonarrError) as exc:
        notifier.send([Finding("sonarr:down", f"Sonarr is unreachable at {cfg.sonarr_url}: {exc}", "error")])
        state.save()
        return []

    findings = health_findings(health, cfg)
    for name, check in (("import lists", check_import_lists), ("queue", check_queue)):
        try:
            findings += check(sonarr, state, cfg, health, now)
        except (requests.RequestException, SonarrError) as exc:
            log.exception("%s check failed", name)
            findings.append(Finding(f"check:{name}", f"The {name} check failed: {exc}", "error"))

    try:
        diagnosis = escalate(sonarr, state, cfg, findings)
    except Exception:  # escalation is best-effort; never lose the notification over it
        log.exception("Escalation failed")
        diagnosis = None
    notifier.send(findings, diagnosis)
    state.save()
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Sonarr health agent")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    sonarr = Sonarr(cfg.sonarr_url, cfg.sonarr_api_key)
    state = State(cfg.state_path)
    notifier = Notifier(cfg.notify_urls, cfg.renotify_hours, state, cfg.dry_run)
    log.info(
        "Starting: sonarr=%s dry_run=%s escalation=%s llm_actions=%s interval=%smin",
        cfg.sonarr_url, cfg.dry_run, cfg.escalation_enabled, cfg.llm_actions, cfg.interval_minutes,
    )

    while True:
        try:
            findings = run_cycle(cfg, sonarr, state, notifier)
            log.info("Cycle done: %d finding(s)", len(findings))
        except Exception:  # keep the daemon alive; next cycle may succeed
            log.exception("Cycle crashed")
        if args.once:
            return
        time.sleep(cfg.interval_minutes * 60)


if __name__ == "__main__":
    main()
