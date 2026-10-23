"""Environment-driven configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw and raw.strip() else default


def _list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


@dataclass
class Config:
    sonarr_url: str
    sonarr_api_key: str
    # URL used in notification links; defaults to sonarr_url (often a container hostname).
    sonarr_public_url: str = ""

    interval_minutes: int = 10
    dry_run: bool = True
    state_path: str = "/data/state.json"

    notify_urls: list[str] = field(default_factory=list)
    renotify_hours: int = 12
    health_ignore: list[str] = field(default_factory=lambda: ["UpdateCheck"])

    # Queue remediation thresholds
    stall_minutes: int = 60
    failed_pending_minutes: int = 30
    import_pending_minutes: int = 30
    mass_stall_threshold: int = 3
    remove_rejected: bool = True

    # Import lists
    trakt_retry_hours: int = 6

    # LLM diagnosis via OpenCode Go (OpenAI-compatible Chat Completions)
    opencode_api_key: str = ""
    opencode_model: str = "glm-5.2"
    opencode_base_url: str = "https://opencode.ai/inference/go/openai/v1"
    llm_actions: bool = False
    escalate_cooldown_hours: int = 24

    @property
    def escalation_enabled(self) -> bool:
        return bool(self.opencode_api_key)

    @property
    def link_base(self) -> str:
        return (self.sonarr_public_url or self.sonarr_url).rstrip("/")

    @classmethod
    def from_env(cls) -> "Config":
        url = os.environ.get("SONARR_URL", "").strip()
        key = os.environ.get("SONARR_API_KEY", "").strip()
        if not url or not key:
            raise SystemExit("SONARR_URL and SONARR_API_KEY are required")
        return cls(
            sonarr_url=url.rstrip("/"),
            sonarr_api_key=key,
            sonarr_public_url=os.environ.get("SONARR_PUBLIC_URL", "").strip(),
            interval_minutes=_int("INTERVAL_MINUTES", 10),
            dry_run=_bool("DRY_RUN", True),
            state_path=os.environ.get("STATE_PATH", "/data/state.json"),
            notify_urls=_list("NOTIFY_URLS"),
            renotify_hours=_int("RENOTIFY_HOURS", 12),
            health_ignore=_list("HEALTH_IGNORE", "UpdateCheck"),
            stall_minutes=_int("STALL_MINUTES", 60),
            failed_pending_minutes=_int("FAILED_PENDING_MINUTES", 30),
            import_pending_minutes=_int("IMPORT_PENDING_MINUTES", 30),
            mass_stall_threshold=_int("MASS_STALL_THRESHOLD", 3),
            remove_rejected=_bool("REMOVE_REJECTED", True),
            trakt_retry_hours=_int("TRAKT_RETRY_HOURS", 6),
            opencode_api_key=os.environ.get("OPENCODE_API_KEY", "").strip(),
            opencode_model=os.environ.get("OPENCODE_MODEL", "").strip() or "glm-5.2",
            opencode_base_url=os.environ.get("OPENCODE_BASE_URL", "").strip() or "https://opencode.ai/inference/go/openai/v1",
            llm_actions=_bool("LLM_ACTIONS", False),
            escalate_cooldown_hours=_int("ESCALATE_COOLDOWN_HOURS", 24),
        )
