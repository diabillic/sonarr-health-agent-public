# sonarr-health-agent

A small service that watches a Sonarr v4 instance (SABnzbd + Trakt lists), fixes the
routine breakages itself, and hands anything unusual to an LLM (via OpenCode Go) for a
diagnosis that lands in your notifications. Runs as a systemd service in a Proxmox LXC, deployed by GitHub
Actions on a self-hosted runner in a second LXC.

## What it does each cycle

| Problem | Detection | Fix |
|---|---|---|
| Trakt list auth broken | Token `expires` in the past, or list named in the `ImportListStatusCheck` health warning **and** the provider test fails | Back-date `expires` (PUT with `forceSave=true`), run `ImportListSync` for that list so Sonarr renews via its stored refresh token, verify with the provider test. If the refresh token is dead, notify with the one-click re-auth path. Retries at most every `TRAKT_RETRY_HOURS`. |
| Import blocked, clean files available | `trackedDownloadState=importBlocked`; manual-import candidates have series + episodes and no rejections (e.g. "matched to series by ID") | `ManualImport` command for those files (samples etc. left behind) |
| Import blocked, release is useless | Every candidate permanently rejected as not-an-upgrade / sample / already imported | Remove from SABnzbd + blocklist, no re-search |
| Import blocked, anything else | Unknown rejection, no files visible (path mapping) | Escalate |
| Stuck importing | `importPending`/`importing` for `IMPORT_PENDING_MINUTES` | `RefreshMonitoredDownloads` once; escalate at 3× threshold |
| Failed in SABnzbd but not processed | `failedPending` for `FAILED_PENDING_MINUTES` | Remove + blocklist + search again |
| Stalled download | `sizeleft` unchanged for `STALL_MINUTES` | Remove + blocklist + search again |
| Many stalls at once / download client health warning | ≥ `MASS_STALL_THRESHOLD` stalled, or `DownloadClient*` health issue | **No blocklisting** (SABnzbd is probably paused or out of disk); escalate |
| Other health warnings/errors | `/api/v3/health` | Notify + escalate (`HEALTH_IGNORE` filters noise) |

Season packs are one download with many queue records; everything is grouped by
`downloadId` so each download is acted on once.

## LLM diagnosis (OpenCode Go)

Set `OPENCODE_API_KEY` (from the [OpenCode console](https://opencode.ai/console), Go plan) to
enable. Unresolved findings go to `OPENCODE_MODEL` (default `glm-5.2`) through OpenCode Go's
OpenAI-compatible endpoint `https://opencode.ai/inference/go/openai/v1/chat/completions`, with
read-only tools: health, queue, manual-import candidates, recent logs, import lists, and root
folders / remote path mappings / download clients / disk space. Secrets are redacted before
anything is sent. The same issue set is only escalated once per `ESCALATE_COOLDOWN_HOURS`, so a
persistent warning costs one diagnosis a day, not one per cycle.

The model must be one Go serves over **Chat Completions** (e.g. `glm-5.2`, `glm-5.3`, `kimi-k3`,
`deepseek-v4-pro`, `mimo-v2.6-pro`); Responses-API and Anthropic-Messages models on Go won't
work with this client. List models: `curl https://opencode.ai/inference/go/v1/models`.

`LLM_ACTIONS=true` additionally lets the model remove/blocklist a queue item, import specific
files, or run `RefreshMonitoredDownloads` / `ImportListSync` / `CheckHealth`. Off by default.

## Deployment

```
 GitHub ──push──▶ runner LXC (gh-runner) ──ssh deploy@──▶ agent LXC (sonarr-agent) ──▶ Sonarr API
                  self-hosted, labels               systemd: sonarr-agent.service
                  proxmox,lan                       /opt/sonarr-agent, /etc/sonarr-agent/agent.env
```

Both LXCs are unprivileged Debian on the Proxmox host, using DHCP (add reservations for
their MACs).

**Every push to `main`:** tests run on a GitHub-hosted runner, then (once you've set up your own
runner and `AGENT_HOST`) the deploy job renders `agent.env` from repo variables + secrets, rsyncs
code to `deploy@AGENT_HOST:staging/`, and runs `sudo sonarr-agent-install`. That root-owned
installer (the only thing `deploy` may sudo) rebuilds the venv if `requirements.txt` changed,
swaps in the new code, writes the systemd unit, restarts, and **rolls back to the previous
release** if the service isn't up after 20s. Pull requests run tests only.

### One-time provisioning

From an admin workstation with root SSH to the Proxmox host and the GitHub CLI (`gh`) logged in,
run this inside your clone of the repo:

```bash
PVE_HOST=root@<proxmox-ip> deploy/provision.sh   # STORAGE=, BRIDGE=, VLAN=, RUNNER_CTID=, AGENT_CTID= to override
```

It creates both LXCs (re-runs reuse them by hostname), installs and registers a self-hosted
runner for your repository, generates the runner's deploy key and authorises it on the agent,
pins the agent's SSH host key on the runner, and sets the `AGENT_HOST` repo variable. The target
repository is detected from the clone (`gh repo view`); set `GH_REPO=owner/name` to override.

`deploy/lxc/sonarr-agent-install` is installed root-owned at bootstrap and deliberately **not**
updated by CI deploys. After changing it, re-run `deploy/provision.sh`.

### Self-hosted runners and public repositories

GitHub advises against attaching self-hosted runners to public repositories, because a pull
request from a fork could run code on your hardware. This workflow runs tests on GitHub-hosted
runners and never runs the deploy job for pull requests, but to be safe:

- Deploy from a **private** copy of this repository, or
- If you keep it public, set Settings → Actions → General → "Fork pull request workflows" to
  require approval for all outside collaborators, and never add the `self-hosted` label to a job
  that runs on `pull_request`.

## Secrets and variables (required before the first deploy)

This repository contains **no secrets**. Add them yourself under **GitHub → Settings → Secrets and
variables → Actions** before the first deploy. The deploy job stops with a clear error if a
required value is missing. Every setting is also documented in `.env.example`.

### Secrets

| Secret | Required | Expected value |
|---|---|---|
| `SONARR_API_KEY` | **yes** | Sonarr's API key: Sonarr → Settings → General → Security → API Key. A 32-character hex string, e.g. `0123456789abcdef0123456789abcdef`. |
| `NOTIFY_URLS` | recommended | One or more [Apprise](https://github.com/caronc/apprise/wiki) URLs, comma separated, e.g. `discord://<webhook_id>/<webhook_token>`, `ntfy://ntfy.sh/<topic>`, `pover://<user_key>@<app_token>`. Without it, findings only go to the agent's log. |
| `OPENCODE_API_KEY` | optional | An [OpenCode](https://opencode.ai/console) API key on the Go plan. Enables LLM diagnosis; leave unset to run rules only. |

### Variables

| Variable | Required | Expected value |
|---|---|---|
| `AGENT_HOST` | **yes** | IP or hostname of the agent LXC. `provision.sh` sets it; the deploy job is skipped until it exists. |
| `SONARR_URL` | **yes** | Sonarr's base URL as reachable **from the agent LXC**, e.g. `http://192.168.1.10:8989`. |
| `SONARR_PUBLIC_URL` | optional | URL you open in a browser, used for links in notifications. Defaults to `SONARR_URL`. |
| `DRY_RUN` | optional | `true` (default) logs what it would do; set `false` once you trust it. |
| `LLM_ACTIONS` | optional | `false` (default). `true` lets the model remove/blocklist queue items, import files and run safe commands. |
| `INTERVAL_MINUTES`, `STALL_MINUTES`, `MASS_STALL_THRESHOLD`, `HEALTH_IGNORE`, `OPENCODE_MODEL`, `OPENCODE_BASE_URL` | optional | Overrides; see `.env.example` for defaults. |

Changing a variable or secret takes effect on the next deploy: re-run the workflow
(Actions → test-and-deploy → Run workflow).

### Operating

```bash
ssh root@<agent-ip> journalctl -u sonarr-agent -f      # live log
ssh root@<agent-ip> systemctl status sonarr-agent
cat /opt/sonarr-agent/app/REVISION                     # deployed commit
```

State (stall timers, cooldowns, notification dedupe) is `/var/lib/sonarr-agent/state.json`;
deleting it just restarts the timers.

## Agent bus (MCP for an assistant such as Hermes Agent)

Optional. When `AGENT_BUS_TOKEN` is set, the agent serves its tools at `http://<agent>:8765/mcp`
(Streamable HTTP MCP, bearer token) so an assistant you chat with, for example
[Hermes Agent](https://hermes-agent.nousresearch.com) on Discord, can answer questions with live
data: `agent_status`, `agent_last_diagnosis`, `agent_run_check` and the agent's domain tools.

**Actions always need your approval.** MCP clients generally run any tool their model picks, so
destructive tools never run unapproved. `APPROVAL_MODE` picks who asks you:

- **`code`** (default, enforced by the agent): a call only queues the action and the agent sends a
  one-time 6-digit code to `APPROVAL_NOTIFY_URLS`, a channel your assistant **cannot read**. You
  give the assistant the code and it calls `confirm_action(action_id, code)`, which runs exactly
  the stored call. Codes expire in 15 minutes, work once, and three wrong codes cancel.
- **`client`** (buttons in your assistant): the Hermes plugin [`integrations/hermes/homelab-approvals`](integrations/hermes/homelab-approvals) shows
  **Allow / Deny** buttons before every destructive agent tool, and the agent trusts that. Each
  action is announced to `APPROVAL_NOTIFY_URLS` **before** it runs (if the announcement fails, it
  doesn't run) and its result after, so you see everything that runs. Trade-off: if your assistant
  runs shell commands unsandboxed, its model could read the bus token and call the agent directly,
  bypassing the buttons; `code` mode isn't affected by that.

Without `APPROVAL_NOTIFY_URLS`, actions are refused in both modes.

Install the plugin: copy the folder to `~/.hermes/plugins/homelab-approvals/`, run
`hermes plugins enable homelab-approvals`, and restart the gateway. It gates the MCP servers named
in `AGENT_BUS_SERVERS` (default `sonarr,unraid,patch`), reads which tools are destructive from the agents'
annotations, and asks for every tool if it can't.

How long Hermes waits for an answer is `approvals.timeout` in `~/.hermes/config.yaml` (seconds,
default 300). Discord buttons expire sooner: `approvals.discord_prompt_timeout` is capped by Hermes
at 900. After that, reply `/approve` or `/deny` in the same channel until `approvals.timeout`
runs out. While an approval is pending, that conversation waits on it.

| Kind | Name | Expected value |
|---|---|---|
| secret | `AGENT_BUS_TOKEN` | A long random string, also given to your MCP client as `Authorization: Bearer <token>`. Unset disables the endpoint. |
| variable | `APPROVAL_MODE` | `code` (default) or `client` (see above) |
| secret | `APPROVAL_NOTIFY_URLS` | Apprise URL(s) for a channel the assistant can't see, e.g. a Discord webhook `https://discord.com/api/webhooks/<id>/<token>` for a channel where the assistant's bot is denied View Channel. |
| variable | `AGENT_BUS_PORT` | optional, default `8765` |
| variable | `BOT_ALERT_URL` | optional: POST alerts to a bot endpoint instead of `NOTIFY_URLS` (falls back to `NOTIFY_URLS`) |

Example Hermes `~/.hermes/config.yaml` entry (token kept in `~/.hermes/.env`):

```yaml
mcp_servers:
  sonarr:
    url: "http://192.168.1.21:8765/mcp"
    headers:
      Authorization: "Bearer ${AGENT_BUS_TOKEN}"
    timeout: 180
```

## Develop

```bash
pip install -r requirements.txt pytest
pytest -q
python -m sonarr_agent --once   # with SONARR_URL / SONARR_API_KEY / STATE_PATH exported
```
