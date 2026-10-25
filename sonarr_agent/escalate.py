"""Hand problems the rules can't classify to an LLM via OpenCode Go, with read-only Sonarr tools.

Uses OpenCode Go's OpenAI-compatible Chat Completions endpoint, so OPENCODE_MODEL must be a
Chat Completions model (glm-*, kimi-*, deepseek-*, mimo-*, hy*, ...), not a Responses or
Anthropic-Messages one. Write tools (remove/blocklist, manual import, a few safe commands)
are only exposed when LLM_ACTIONS=true, and still honour DRY_RUN.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

import requests

from .config import Config
from .findings import Finding
from .sonarr import Sonarr, SonarrError, field_value
from .state import State

log = logging.getLogger(__name__)

USER_AGENT = "sonarr-health-agent/1.0"
MAX_TURNS = 15
SECRET_RE = re.compile(r"(?i)(api[_-]?key|apikey|token|password|secret)([\"'=:\s]+)([^\s&\"',}]+)")
SAFE_COMMANDS = ["RefreshMonitoredDownloads", "ImportListSync", "CheckHealth"]

SYSTEM_PROMPT = """You are the on-call diagnostician for a home media stack: Sonarr (v4 or v5) in Docker, \
SABnzbd as the download client, and Trakt import lists. A rule-based agent has already handled \
the routine cases (Trakt token renewal, blocked imports with clean candidates, stalled or failed \
downloads) and is handing you the problems it could not resolve.

Use the tools to investigate the actual state before concluding anything. Common root causes: \
remote path mappings or Docker volume paths that differ between SABnzbd and Sonarr, file \
permissions (PUID/PGID), a full disk, SABnzbd paused or its news server failing, series or \
episode mapping problems (anime absolute numbering, scene numbering), and expired credentials.

Your reply is sent as a push notification, so keep it under 200 words of plain text: one line per \
problem with the likely cause, then numbered concrete steps for the human (exact Sonarr settings \
page, path, or command). Say plainly when evidence is inconclusive rather than guessing. If action \
tools are available, only take an action when the evidence clearly supports it, and say what you did."""


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    fn: Callable[..., str]

    def spec(self) -> dict:
        return {"type": "function", "function": {"name": self.name, "description": self.description, "parameters": self.parameters}}


def _schema(props: dict | None = None, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props or {}, "required": required or [], "additionalProperties": False}


def _redact(obj: Any) -> str:
    text = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    return SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", text)


def _fingerprint(findings: list[Finding]) -> str:
    return hashlib.sha256("|".join(sorted(f.key for f in findings)).encode()).hexdigest()[:16]


def _build_tools(sonarr: Sonarr, cfg: Config) -> list[Tool]:
    def call(fn, *args, **kwargs) -> str:
        try:
            return _redact(fn(*args, **kwargs))
        except SonarrError as exc:
            return f"Error: {exc}"

    def get_health() -> str:
        # HEALTH_IGNORE applies here too, so diagnoses don't keep raising checks the operator muted.
        return call(lambda: [
            {k: h.get(k) for k in ("source", "type", "message")}
            for h in sonarr.health() if h.get("source") not in cfg.health_ignore
        ])

    def get_queue() -> str:
        keys = ("id", "downloadId", "title", "status", "trackedDownloadStatus", "trackedDownloadState",
                "statusMessages", "errorMessage", "sizeleft", "size", "outputPath", "downloadClient", "added")
        return call(lambda: [{k: r.get(k) for k in keys} for r in sonarr.queue()])

    def get_manual_import_candidates(download_id: str) -> str:
        def fetch():
            return [
                {
                    "path": c.get("path"),
                    "series": (c.get("series") or {}).get("title"),
                    "seasonNumber": c.get("seasonNumber"),
                    "episodes": [f"S{e.get('seasonNumber')}E{e.get('episodeNumber')}" for e in c.get("episodes") or []],
                    "quality": ((c.get("quality") or {}).get("quality") or {}).get("name"),
                    "rejections": c.get("rejections"),
                }
                for c in sonarr.manual_import_candidates(download_id)
            ]
        return call(fetch)

    def get_recent_logs(level: str = "warn", count: int = 40) -> str:
        def fetch():
            return [
                {"time": e.get("time"), "logger": e.get("logger"), "message": e.get("message"),
                 "exception": (e.get("exception") or "").splitlines()[:3]}
                for e in sonarr.logs(level, min(int(count), 100))
            ]
        return call(fetch)

    def get_import_lists() -> str:
        return call(lambda: [
            {"id": l.get("id"), "name": l.get("name"), "implementation": l.get("implementation"),
             "enableAutomaticAdd": l.get("enableAutomaticAdd"), "expires": field_value(l, "expires"),
             "authUser": field_value(l, "authUser")}
            for l in sonarr.import_lists()
        ])

    def get_paths_and_storage() -> str:
        def fetch():
            return {
                "rootFolders": [{"path": r.get("path"), "accessible": r.get("accessible"), "freeSpace": r.get("freeSpace")} for r in sonarr.root_folders()],
                "remotePathMappings": sonarr.remote_path_mappings(),
                "downloadClients": [
                    {"name": d.get("name"), "implementation": d.get("implementation"), "enable": d.get("enable"),
                     "host": field_value(d, "host"), "port": field_value(d, "port"), "category": field_value(d, "tvCategory")}
                    for d in sonarr.download_clients()
                ],
                "diskSpace": [{"path": d.get("path"), "freeSpace": d.get("freeSpace"), "totalSpace": d.get("totalSpace")} for d in sonarr.disk_space()],
            }
        return call(fetch)

    tools = [
        Tool("get_health", "Current Sonarr health check results (source, type, message).", _schema(), get_health),
        Tool("get_queue", "Summarised Sonarr download queue: id, downloadId, title, status, tracked state, messages, size left, output path.", _schema(), get_queue),
        Tool("get_manual_import_candidates",
             "Files Sonarr would import for a download, with matched series/episodes and rejection reasons.",
             _schema({"download_id": {"type": "string", "description": "The queue item's downloadId."}}, ["download_id"]),
             get_manual_import_candidates),
        Tool("get_recent_logs", "Most recent Sonarr log entries at or above a level.",
             _schema({"level": {"type": "string", "enum": ["info", "warn", "error"]},
                      "count": {"type": "integer", "minimum": 1, "maximum": 100}}),
             get_recent_logs),
        Tool("get_import_lists", "Import lists with type, enabled flags and token expiry (secrets removed).", _schema(), get_import_lists),
        Tool("get_paths_and_storage", "Root folders, remote path mappings, download clients (host/category only), and disk space.", _schema(), get_paths_and_storage),
    ]
    if not cfg.llm_actions:
        return tools

    def act(desc: str, fn) -> str:
        if cfg.dry_run:
            return f"DRY_RUN is on; did not execute: {desc}"
        result = call(fn)
        log.info("LLM action: %s", desc)
        return f"Done: {desc}. {result[:300]}"

    def remove_queue_item(queue_id: int, blocklist: bool, search_again: bool) -> str:
        return act(
            f"remove queue {queue_id} blocklist={blocklist} search_again={search_again}",
            lambda: sonarr.remove_queue_item(queue_id, remove_from_client=True, blocklist=blocklist,
                                             skip_redownload=not search_again),
        )

    def import_files(download_id: str, paths: list[str]) -> str:
        from .queue import _import_file

        def run():
            wanted = set(paths)
            files = [
                _import_file(c, download_id)
                for c in sonarr.manual_import_candidates(download_id)
                if c.get("path") in wanted and c.get("series") and c.get("episodes")
            ]
            if not files:
                raise SonarrError("no matching candidates with a series and episodes")
            return sonarr.manual_import(files)
        return act(f"manual import {len(paths)} file(s) from {download_id}", run)

    def run_command(name: str) -> str:
        if name not in SAFE_COMMANDS:
            return f"Refused: {name} is not in {SAFE_COMMANDS}"
        return act(f"command {name}", lambda: sonarr.command(name))

    return tools + [
        Tool("remove_queue_item", "Remove a download from SABnzbd and the Sonarr queue.",
             _schema({"queue_id": {"type": "integer", "description": "The queue record id (not downloadId)."},
                      "blocklist": {"type": "boolean", "description": "Blocklist the release so it is not grabbed again."},
                      "search_again": {"type": "boolean", "description": "After blocklisting, search for another release."}},
                     ["queue_id", "blocklist", "search_again"]),
             remove_queue_item),
        Tool("import_files", "Manually import specific files from a download, using Sonarr's own series/episode match.",
             _schema({"download_id": {"type": "string"},
                      "paths": {"type": "array", "items": {"type": "string"},
                                "description": "Full file paths exactly as returned by get_manual_import_candidates."}},
                     ["download_id", "paths"]),
             import_files),
        Tool("run_command", "Run a safe Sonarr command.",
             _schema({"name": {"type": "string", "enum": SAFE_COMMANDS}}, ["name"]),
             run_command),
    ]


class OpenCodeGo:
    """Minimal OpenAI-compatible Chat Completions client for OpenCode Go."""

    def __init__(self, cfg: Config):
        self.url = cfg.opencode_base_url.rstrip("/") + "/chat/completions"
        self.model = cfg.opencode_model
        self.http = requests.Session()
        self.http.headers.update({
            "Authorization": f"Bearer {cfg.opencode_api_key}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            # Required by OpenCode Go: one stable id per conversation.
            "x-opencode-session": str(uuid.uuid4()),
        })

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        body = {"model": self.model, "messages": messages, "tools": tools, "tool_choice": "auto", "max_tokens": 4096}
        for attempt in range(3):
            resp = self.http.post(self.url, json=body, timeout=180)
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
            if resp.status_code >= 400:
                raise RuntimeError(f"OpenCode Go {resp.status_code}: {resp.text[:300]}")
            return resp.json()
        raise RuntimeError("unreachable")


def run_agent(client: OpenCodeGo, tools: list[Tool], problems: str) -> str | None:
    by_name = {t.name: t for t in tools}
    specs = [t.spec() for t in tools]
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Unresolved problems from this cycle:\n{problems}"},
    ]
    for _ in range(MAX_TURNS):
        choice = client.complete(messages, specs)["choices"][0]
        msg = choice["message"]
        calls = msg.get("tool_calls") or []
        # Echo the assistant turn back unchanged (some reasoning models require their reasoning field).
        messages.append({k: v for k, v in msg.items() if v is not None})
        if not calls:
            text = (msg.get("content") or "").strip()
            if choice.get("finish_reason") == "length":
                text += "\n[truncated]"
            return text or None
        for call in calls:
            fn = call.get("function", {})
            tool = by_name.get(fn.get("name"))
            try:
                args = json.loads(fn.get("arguments") or "{}")
                result = tool.fn(**args) if tool else f"Error: unknown tool {fn.get('name')}"
            except (json.JSONDecodeError, TypeError) as exc:
                result = f"Error: invalid arguments ({exc})"
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": result})
    log.warning("Diagnosis stopped after %d turns without a final answer", MAX_TURNS)
    return None


def escalate(sonarr: Sonarr, state: State, cfg: Config, findings: list[Finding]) -> str | None:
    pending = [f for f in findings if f.escalate]
    if not pending or not cfg.escalation_enabled:
        return None
    fp = _fingerprint(pending)
    if state.within("escalated", fp, cfg.escalate_cooldown_hours):
        log.info("Escalation for this issue set already sent within %sh; skipping", cfg.escalate_cooldown_hours)
        return None

    problems = _redact([{"summary": f.summary, "details": f.details} for f in pending])
    try:
        text = run_agent(OpenCodeGo(cfg), _build_tools(sonarr, cfg), problems)
    except (requests.RequestException, RuntimeError, KeyError, IndexError, ValueError) as exc:
        log.error("Diagnosis via OpenCode Go failed: %s", exc)
        return None
    state.mark("escalated", fp)
    return text
