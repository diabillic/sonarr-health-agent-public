"""Hermes plugin: ask the operator (Allow / Deny buttons) before an agent-bus action runs.

Hermes runs MCP tools without asking. This pre_tool_call hook escalates every destructive
tool of the configured agent-bus MCP servers to Hermes's human-approval gate, which shows
Allow / Deny buttons on Discord to allowed users only. Read-only tools pass straight through.

Which tools are destructive comes from each agent's own MCP annotations (fetched on first use,
cached 10 minutes). If an agent's tool list can't be read, every tool of that server asks.
The rule_key is per exact call (tool + argument hash), so "Session" / "Always" can never
silently cover a different action.

Settings (Hermes .env or environment):
  AGENT_BUS_SERVERS  comma-separated mcp_servers names to gate (default: sonarr,unraid,patch)

Pair it with APPROVAL_MODE=client on the agents, which then trust this approval and announce
every action to their audit channel before running it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import urllib.request
from pathlib import Path

log = logging.getLogger("homelab_approvals")

CACHE_SECONDS = 600
FETCH_TIMEOUT = 5
_cache: dict[str, tuple[float, set[str] | None]] = {}
_lock = threading.Lock()


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")


def _env() -> dict[str, str]:
    values = dict(os.environ)
    try:
        for line in (_hermes_home() / ".env").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, val = line.partition("=")
                values.setdefault(key.strip(), val.strip().strip('"').strip("'"))
    except OSError:
        pass
    return values


def _watched() -> set[str]:
    raw = _env().get("AGENT_BUS_SERVERS") or "sonarr,unraid,patch"
    return {s.strip() for s in raw.split(",") if s.strip()}


def _load_config() -> dict:
    try:
        from hermes_cli.config import read_raw_config  # Hermes's own loader (no PyYAML in its runtime)
    except ImportError:
        import yaml  # outside Hermes, e.g. tests

        return yaml.safe_load((_hermes_home() / "config.yaml").read_text(encoding="utf-8")) or {}
    return read_raw_config() or {}


def _server_config(name: str) -> tuple[str, dict[str, str]] | None:
    try:
        cfg = _load_config()
    except Exception as exc:  # caller fails closed
        log.warning("homelab-approvals: can't read Hermes config (%s)", exc)
        return None
    server = (cfg.get("mcp_servers") or {}).get(name) or {}
    if not server.get("url"):
        return None
    env = _env()
    expand = lambda v: re.sub(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: env.get(m.group(1), ""), str(v))  # noqa: E731
    return expand(server["url"]), {k: expand(v) for k, v in (server.get("headers") or {}).items()}


def destructive_tools(server: str) -> set[str] | None:
    """Names of the server's tools not annotated read-only; None if they can't be read."""
    with _lock:
        hit = _cache.get(server)
        if hit and time.time() - hit[0] < CACHE_SECONDS:
            return hit[1]
    found: set[str] | None = None
    conf = _server_config(server)
    if conf:
        url, headers = conf
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={**headers, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                tools = json.load(resp)["result"]["tools"]
            found = {t["name"] for t in tools if (t.get("annotations") or {}).get("readOnlyHint") is not True}
        except Exception as exc:  # unreachable, auth, bad JSON: fail closed (ask for everything)
            log.warning("homelab-approvals: can't read %s tool annotations (%s); every tool will ask", server, exc)
    with _lock:
        _cache[server] = (time.time(), found)
    return found


def pre_tool_call(tool_name: str = "", args: dict | None = None, task_id: str = "", **_kwargs):
    m = re.match(r"^mcp__(.+?)__(.+)$", tool_name or "")
    if not m or m.group(1) not in _watched():
        return None
    server, tool = m.groups()
    try:
        destructive = destructive_tools(server)
    except Exception as exc:  # a hook error must still end in a prompt, never a silent run or a crash
        log.warning("homelab-approvals: %s; asking", exc)
        destructive = None
    if destructive is not None and tool not in destructive:
        return None  # read-only: no prompt
    args = args or {}
    shown = ", ".join(f"{k}={json.dumps(v, default=str)}" for k, v in args.items()) or "no arguments"
    digest = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:16]
    note = "" if destructive is not None else " (couldn't read the agent's tool list, so every tool asks)"
    return {
        "action": "approve",
        "message": f"The {server} agent wants to run {tool}({shown}){note}.",
        "rule_key": f"homelab:{server}:{tool}:{digest}",
    }


def register(ctx):
    ctx.register_hook("pre_tool_call", pre_tool_call)
