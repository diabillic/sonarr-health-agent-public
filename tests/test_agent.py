import json
import copy
from datetime import datetime, timedelta, timezone

import pytest

from sonarr_agent.config import Config
from sonarr_agent.escalate import _build_tools, _redact, escalate, run_agent
from sonarr_agent.importlists import BACKDATED_EXPIRY, check_import_lists, parse_dt
from sonarr_agent.queue import check_queue
from sonarr_agent.sonarr import field_value
from sonarr_agent.state import State

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


class FakeSonarr:
    def __init__(self, queue=(), lists=(), candidates=None, renew_ok=True, test_ok=True):
        self._queue = list(queue)
        self._lists = {l["id"]: l for l in lists}
        self._candidates = candidates or {}
        self.renew_ok = renew_ok
        self.test_ok = test_ok
        self.calls = []

    def queue(self):
        return self._queue

    def import_lists(self):
        return list(self._lists.values())

    def import_list(self, list_id):
        return self._lists[list_id]

    def manual_import_candidates(self, dl_id):
        return self._candidates.get(dl_id, [])

    def test_import_list(self, resource):
        return (self.test_ok, [] if self.test_ok else ["401 Unauthorized"])

    def update_import_list(self, resource, force=True):
        self.calls.append(("update_import_list", field_value(resource, "expires"), force))
        self._lists[resource["id"]] = copy.deepcopy(resource)

    def command(self, name, **body):
        self.calls.append(("command", name, body))
        if name == "ImportListSync" and self.renew_ok:
            lst = self._lists[body["definitionId"]]
            for f in lst["fields"]:
                if f["name"] == "expires":
                    f["value"] = (NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z")
            self.test_ok = True
        return {"id": 1}

    def wait_command(self, cid, timeout=180):
        return {"status": "completed"}

    def remove_queue_item(self, qid, **kw):
        self.calls.append(("remove", qid, kw))

    def manual_import(self, files, import_mode="auto"):
        self.calls.append(("manual_import", files))
        return {"id": 2}


def cfg(tmp_path, **kw):
    c = Config(sonarr_url="http://sonarr:8989", sonarr_api_key="k", state_path=str(tmp_path / "s.json"), dry_run=False)
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def trakt_list(expires, access="at", refresh="rt"):
    return {
        "id": 3, "name": "Trakt Watchlist", "implementation": "TraktUserImport",
        "fields": [
            {"name": "accessToken", "value": access},
            {"name": "refreshToken", "value": refresh},
            {"name": "expires", "value": expires},
        ],
    }


def q(id_, dl, **kw):
    rec = {"id": id_, "downloadId": dl, "title": f"Show {dl}", "status": "downloading",
           "trackedDownloadState": "downloading", "sizeleft": 1000}
    rec.update(kw)
    return rec


# --- import lists ---

def test_parse_dt_handles_dotnet_precision():
    assert parse_dt("2026-10-23T12:00:00.1234567Z") == datetime(2026, 10, 23, 12, 0, 0, 123456, tzinfo=timezone.utc)
    assert parse_dt(None) is None


def test_expired_trakt_token_is_backdated_and_resynced(tmp_path):
    s = FakeSonarr(lists=[trakt_list("2026-10-01T00:00:00Z")])
    c = cfg(tmp_path)
    [f] = check_import_lists(s, State(c.state_path), c, [], NOW)
    assert f.resolved and "Renewed" in f.summary
    assert ("update_import_list", BACKDATED_EXPIRY, True) in s.calls
    assert ("command", "ImportListSync", {"definitionId": 3}) in s.calls


def test_flagged_list_with_valid_expiry_but_failing_test_is_renewed(tmp_path):
    s = FakeSonarr(lists=[trakt_list("2027-01-01T00:00:00Z")], test_ok=False)
    c = cfg(tmp_path)
    health = [{"source": "ImportListStatusCheck", "type": "warning", "message": "Lists unavailable due to failures: Trakt Watchlist"}]
    [f] = check_import_lists(s, State(c.state_path), c, health, NOW)
    assert f.resolved


def test_flagged_list_that_passes_test_is_left_alone(tmp_path):
    s = FakeSonarr(lists=[trakt_list("2027-01-01T00:00:00Z")], test_ok=True)
    c = cfg(tmp_path)
    health = [{"source": "ImportListStatusCheck", "type": "warning", "message": "All import lists are unavailable"}]
    assert check_import_lists(s, State(c.state_path), c, health, NOW) == []
    assert s.calls == []


def test_dead_refresh_token_asks_for_reauth_and_backs_off(tmp_path):
    s = FakeSonarr(lists=[trakt_list("2026-10-01T00:00:00Z")], renew_ok=False)
    c = cfg(tmp_path)
    st = State(c.state_path)
    [f] = check_import_lists(s, st, c, [], NOW)
    assert not f.resolved and "Authenticate with Trakt" in f.summary
    s.calls.clear()
    [f2] = check_import_lists(s, st, c, [], NOW + timedelta(hours=1))
    assert "already tried" in f2.summary and s.calls == []


def test_dry_run_makes_no_changes(tmp_path):
    s = FakeSonarr(lists=[trakt_list("2026-10-01T00:00:00Z")], queue=[q(1, "a", trackedDownloadState="failedPending")])
    c = cfg(tmp_path, dry_run=True, failed_pending_minutes=0)
    st = State(c.state_path)
    fs = check_import_lists(s, st, c, [], NOW) + check_queue(s, st, c, [], NOW)
    assert all(f.summary.startswith("[dry run]") for f in fs) and len(fs) == 2
    assert s.calls == []


# --- queue ---

def test_stalled_download_blocklisted_after_threshold(tmp_path):
    c = cfg(tmp_path, stall_minutes=60)
    st = State(c.state_path)
    s = FakeSonarr(queue=[q(1, "a")])
    assert check_queue(s, st, c, [], NOW) == []
    assert check_queue(s, st, c, [], NOW + timedelta(minutes=30)) == []
    [f] = check_queue(s, st, c, [], NOW + timedelta(minutes=61))
    assert f.resolved
    assert s.calls == [("remove", 1, {"remove_from_client": True, "blocklist": True, "skip_redownload": False})]


def test_progress_resets_stall_timer(tmp_path):
    c = cfg(tmp_path, stall_minutes=60)
    st = State(c.state_path)
    check_queue(FakeSonarr(queue=[q(1, "a", sizeleft=1000)]), st, c, [], NOW)
    s = FakeSonarr(queue=[q(1, "a", sizeleft=500)])
    assert check_queue(s, st, c, [], NOW + timedelta(minutes=61)) == []


def test_mass_stall_escalates_instead_of_blocklisting(tmp_path):
    c = cfg(tmp_path, stall_minutes=60, mass_stall_threshold=3)
    st = State(c.state_path)
    s = FakeSonarr(queue=[q(i, f"d{i}") for i in range(3)])
    check_queue(s, st, c, [], NOW)
    [f] = check_queue(s, st, c, [], NOW + timedelta(minutes=61))
    assert f.escalate and f.key == "queue:mass-stall"
    assert s.calls == []


def test_season_pack_records_handled_once(tmp_path):
    c = cfg(tmp_path, failed_pending_minutes=0)
    recs = [q(i, "pack", trackedDownloadState="failedPending") for i in (1, 2, 3)]
    s = FakeSonarr(queue=recs)
    fs = check_queue(s, State(c.state_path), c, [], NOW)
    assert len(fs) == 1 and [x[0] for x in s.calls] == ["remove"]


def test_import_blocked_with_clean_candidates_is_imported(tmp_path):
    c = cfg(tmp_path)
    cand = {"path": "/downloads/tv/x/ep.mkv", "series": {"id": 9, "title": "X"}, "episodes": [{"id": 77}],
            "rejections": [], "quality": {"quality": {"name": "WEBDL-1080p"}}, "languages": [{"id": 1}]}
    sample = {"path": "/downloads/tv/x/sample.mkv", "series": {"id": 9}, "episodes": [{"id": 77}],
              "rejections": [{"reason": "Sample", "type": "permanent"}]}
    s = FakeSonarr(queue=[q(1, "a", status="completed", trackedDownloadState="importBlocked")],
                   candidates={"a": [cand, sample]})
    [f] = check_queue(s, State(c.state_path), c, [], NOW)
    assert f.resolved and "1 rejected" in f.summary
    [(name, files)] = s.calls
    assert name == "manual_import" and files[0]["seriesId"] == 9 and files[0]["episodeIds"] == [77]


def test_import_blocked_not_an_upgrade_is_removed_without_research(tmp_path):
    c = cfg(tmp_path)
    cand = {"path": "/d/ep.mkv", "series": {"id": 9}, "episodes": [{"id": 77}],
            "rejections": [{"reason": "Not an upgrade for existing episode file(s)", "type": "permanent"}]}
    s = FakeSonarr(queue=[q(1, "a", status="completed", trackedDownloadState="importBlocked")], candidates={"a": [cand]})
    [f] = check_queue(s, State(c.state_path), c, [], NOW)
    assert f.resolved
    assert s.calls == [("remove", 1, {"remove_from_client": True, "blocklist": True, "skip_redownload": True})]


def test_import_blocked_unknown_reason_escalates(tmp_path):
    c = cfg(tmp_path)
    cand = {"path": "/d/ep.mkv", "series": {"id": 9}, "episodes": [],
            "rejections": [{"reason": "Unable to identify correct episode(s) using release name", "type": "permanent"}]}
    s = FakeSonarr(queue=[q(1, "a", status="completed", trackedDownloadState="importBlocked")], candidates={"a": [cand]})
    [f] = check_queue(s, State(c.state_path), c, [], NOW)
    assert f.escalate and not f.resolved and s.calls == []


def test_import_blocked_no_files_escalates_as_path_problem(tmp_path):
    c = cfg(tmp_path)
    s = FakeSonarr(queue=[q(1, "a", status="completed", trackedDownloadState="importBlocked")])
    [f] = check_queue(s, State(c.state_path), c, [], NOW)
    assert f.escalate and "remote path mapping" in f.summary


def test_import_pending_nudged_then_escalated(tmp_path):
    c = cfg(tmp_path, import_pending_minutes=30)
    st = State(c.state_path)
    s = FakeSonarr(queue=[q(1, "a", status="completed", trackedDownloadState="importPending")])
    assert check_queue(s, st, c, [], NOW) == []
    [f] = check_queue(s, st, c, [], NOW + timedelta(minutes=31))
    assert f.resolved and ("command", "RefreshMonitoredDownloads", {}) in s.calls
    assert check_queue(s, st, c, [], NOW + timedelta(minutes=60)) == []
    [f] = check_queue(s, st, c, [], NOW + timedelta(minutes=91))
    assert f.escalate


def test_state_pruned_when_download_leaves_queue(tmp_path):
    c = cfg(tmp_path)
    st = State(c.state_path)
    check_queue(FakeSonarr(queue=[q(1, "a")]), st, c, [], NOW)
    assert "a" in st["progress"]
    check_queue(FakeSonarr(queue=[]), st, c, [], NOW)
    assert st["progress"] == {}


# --- escalation plumbing ---

def test_redact_masks_secrets():
    out = _redact({"msg": "GET http://sab:8080/api?apikey=abc123&mode=queue", "password": "hunter2"})
    assert "abc123" not in out and "hunter2" not in out


@pytest.mark.parametrize("actions,expected", [(False, 6), (True, 9)])
def test_tool_schemas_build(tmp_path, actions, expected):
    tools = _build_tools(FakeSonarr(), cfg(tmp_path, llm_actions=actions))
    assert len(tools) == expected
    for t in tools:
        fn = t.spec()["function"]
        assert fn["name"] and fn["parameters"]["type"] == "object"
        # every required param must exist as a real function argument
        assert set(fn["parameters"]["required"]) <= set(t.fn.__code__.co_varnames)


class ScriptedLLM:
    """Plays back chat-completions responses and records what was sent."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    def complete(self, messages, tools):
        self.sent.append(copy.deepcopy(messages))
        return {"choices": [self.replies.pop(0)]}


def test_agent_loop_runs_tools_and_returns_text(tmp_path):
    s = FakeSonarr(candidates={"a": [{"path": "/d/x.mkv", "series": {"title": "X"}, "episodes": [],
                                      "rejections": [{"reason": "Unknown Series", "type": "permanent"}]}]})
    llm = ScriptedLLM([
        {"finish_reason": "tool_calls", "message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "get_manual_import_candidates", "arguments": '{"download_id": "a"}'}},
            {"id": "c2", "type": "function", "function": {"name": "nope", "arguments": "{}"}},
        ]}},
        {"finish_reason": "stop", "message": {"role": "assistant", "content": "1. Fix the series mapping."}},
    ])
    out = run_agent(llm, _build_tools(s, cfg(tmp_path)), "problems")
    assert out == "1. Fix the series mapping."
    tool_msgs = [m for m in llm.sent[1] if m["role"] == "tool"]
    assert [m["tool_call_id"] for m in tool_msgs] == ["c1", "c2"]
    assert "Unknown Series" in tool_msgs[0]["content"] and "unknown tool" in tool_msgs[1]["content"]
    assert llm.sent[1][2]["tool_calls"][0]["id"] == "c1"  # assistant turn echoed back before results


def test_agent_loop_survives_bad_arguments(tmp_path):
    llm = ScriptedLLM([
        {"finish_reason": "tool_calls", "message": {"role": "assistant", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "get_recent_logs", "arguments": "{not json"}}]}},
        {"finish_reason": "stop", "message": {"role": "assistant", "content": "done"}},
    ])
    assert run_agent(llm, _build_tools(FakeSonarr(), cfg(tmp_path)), "p") == "done"
    assert "invalid arguments" in llm.sent[1][-1]["content"]


def test_get_health_tool_hides_ignored_sources(tmp_path):
    s = FakeSonarr()
    s.health = lambda: [{"source": "AllowedHostsCheck", "type": "warning", "message": "a"},
                        {"source": "IndexerStatusCheck", "type": "error", "message": "b"}]
    tools = {t.name: t for t in _build_tools(s, cfg(tmp_path, health_ignore=["AllowedHostsCheck"]))}
    out = tools["get_health"].fn()
    assert "IndexerStatusCheck" in out and "AllowedHostsCheck" not in out


def test_escalation_disabled_without_key(tmp_path):
    from sonarr_agent.findings import Finding
    c = cfg(tmp_path)
    assert escalate(FakeSonarr(), State(c.state_path), c, [Finding("k", "x", escalate=True)]) is None


# --- agent bus (MCP endpoint for the Discord bot, alert hand-off) ---

class FakeOutbox:
    def __init__(self, sent, ok=True):
        self.sent, self.ok = sent, ok

    def __len__(self):
        return 1

    def send(self, msg):
        self.sent.append((msg.title, msg.markdown()))
        return self.ok


def test_approvals_codes_attempts_expiry_and_fail_closed():
    from sonarr_agent.bus import Approvals, BusTool, schema
    ran = []
    tool = BusTool("remove_queue_item", "remove", schema(), lambda queue_id: ran.append(queue_id) or "removed", read_only=False)
    sent = []
    ap = Approvals("sonarr", [])
    assert ap.request(tool, {"queue_id": 1})["status"] == "refused"  # no approval channel: no actions
    ap.outbox = FakeOutbox(sent)
    req = ap.request(tool, {"queue_id": 1})
    code = sent[-1][0].split()[-1]
    assert len(code) == 6 and code.isdigit() and code not in json.dumps(req) and ran == []
    wrong = "000000" if code != "000000" else "111111"
    assert "2 attempt(s) left" in ap.confirm(req["action_id"], wrong)["reason"]
    assert "1 attempt(s) left" in ap.confirm(req["action_id"], wrong)["reason"]
    assert "cancelled" in ap.confirm(req["action_id"], wrong)["reason"] and "cancelled" in sent[-1][0]
    assert ap.confirm(req["action_id"], code)["status"] == "refused" and ran == []  # gone after 3 misses
    req = ap.request(tool, {"queue_id": 2})
    ap._pending[req["action_id"]].expires = 0  # expired
    assert ap.confirm(req["action_id"], sent[-1][0].split()[-1])["status"] == "refused" and ran == []
    req = ap.request(tool, {"queue_id": 3})
    assert ap.cancel(req["action_id"])["status"] == "cancelled"
    ap.outbox = FakeOutbox(sent, ok=False)  # code can't be delivered: nothing is queued
    assert ap.request(tool, {"queue_id": 4})["status"] == "refused" and not ap._pending


def _rpc(url, token, method, params=None, id_=1):
    import requests
    body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if id_ is not None:
        body["id"] = id_
    return requests.post(url, json=body, headers={"Authorization": f"Bearer {token}"}, timeout=5)


def test_bus_mcp_endpoint_end_to_end(tmp_path):
    from sonarr_agent.__main__ import ACTION_TOOLS
    from sonarr_agent.bus import Approvals, BusTool, Runtime, schema, serve_mcp
    from sonarr_agent.findings import Finding

    rt = Runtime("sonarr", revision="abc123")
    rt.record([Finding("dl:x", "'Show' removed and blocklisted.", "info", resolved=True)], "1. do the thing")
    tools = rt.common_tools(check_is_destructive=True) + [
        BusTool("get_queue", "queue", schema(), lambda: [{"id": 1}]),
        BusTool("remove_queue_item", "remove", schema({"queue_id": {"type": "integer"}}, ["queue_id"]),
                lambda queue_id: f"removed {queue_id}", read_only=False),
        BusTool("boom", "fails", schema(), lambda: 1 / 0),
    ]
    approvals, sent = Approvals("sonarr", []), []
    approvals.outbox = FakeOutbox(sent)
    server = serve_mcp("127.0.0.1", 0, "s3cret", tools, "sonarr-agent", approvals)
    url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
    try:
        assert _rpc(url, "wrong", "tools/list").status_code == 401
        init = _rpc(url, "s3cret", "initialize", {"protocolVersion": "2025-06-18"}).json()["result"]
        assert init["serverInfo"]["name"] == "sonarr-agent" and "tools" in init["capabilities"]
        assert _rpc(url, "s3cret", "notifications/initialized", id_=None).status_code == 202
        listed = {t["name"]: t["annotations"] for t in _rpc(url, "s3cret", "tools/list").json()["result"]["tools"]}
        assert listed["get_queue"]["readOnlyHint"] and listed["remove_queue_item"]["destructiveHint"]
        assert listed["agent_run_check"]["destructiveHint"]  # sonarr checks can apply fixes when not in dry run
        status = _rpc(url, "s3cret", "tools/call", {"name": "agent_status", "arguments": {}}).json()["result"]
        assert '"dl:x"' in status["content"][0]["text"] and not status["isError"]
        # A destructive call only queues the action; the code goes out of band, never to the caller.
        res = _rpc(url, "s3cret", "tools/call", {"name": "remove_queue_item", "arguments": {"queue_id": 7}}).json()["result"]
        pending = json.loads(res["content"][0]["text"])
        code = sent[-1][0].split()[-1]
        assert pending["status"] == "approval_required" and code not in res["content"][0]["text"]
        assert listed["confirm_action"]["destructiveHint"] and "cancel_action" in listed
        confirm = {"name": "confirm_action", "arguments": {"action_id": pending["action_id"], "code": code}}
        done = json.loads(_rpc(url, "s3cret", "tools/call", confirm).json()["result"]["content"][0]["text"])
        assert done == {"status": "approved", "action": "remove_queue_item(queue_id=7)", "result": "removed 7"}
        again = json.loads(_rpc(url, "s3cret", "tools/call", confirm).json()["result"]["content"][0]["text"])
        assert again["status"] == "refused"  # single use
        assert _rpc(url, "s3cret", "tools/call", {"name": "boom", "arguments": {}}).json()["result"]["isError"]
        assert _rpc(url, "s3cret", "tools/call", {"name": "get_queue", "arguments": {"x": 1}}).json()["result"]["isError"]
        assert "error" in _rpc(url, "s3cret", "tools/call", {"name": "nope"}).json()
        assert _rpc(url, "s3cret", "agent_run_check").json()["error"]["code"] == -32601
        _rpc(url, "s3cret", "tools/call", {"name": "agent_run_check", "arguments": {}})
        assert not rt.wake.is_set()  # a check that can apply fixes is gated too
    finally:
        server.shutdown()
    assert ACTION_TOOLS == {"remove_queue_item", "import_files", "run_command"}


def test_bus_tools_mark_sonarr_actions_destructive(tmp_path):
    from sonarr_agent.__main__ import bus_tools
    from sonarr_agent.bus import Runtime
    tools = {t.name: t for t in bus_tools(cfg(tmp_path), Runtime("sonarr"))}
    assert not tools["remove_queue_item"].read_only and not tools["import_files"].read_only
    assert tools["get_queue"].read_only and tools["agent_status"].read_only


def test_alerts_go_to_bot_first_then_fall_back(tmp_path, monkeypatch):
    from sonarr_agent import notify
    from sonarr_agent.findings import Finding
    sent, pushed = [], []
    st = State(str(tmp_path / "s.json"))
    n = notify.Notifier([], 12, st, bot_url="http://bot:8766/alert", bot_token="t")
    n.outbox = type("O", (), {"send": lambda s, msg: sent.append(msg.title) or True})()
    monkeypatch.setattr(notify, "push_alert", lambda *a: pushed.append(a[2:5]) or True)
    n.send([Finding("k1", "broken", "error")])
    assert len(pushed) == 1 and pushed[0][0] == "sonarr" and sent == []
    monkeypatch.setattr(notify, "push_alert", lambda *a: False)  # bot down: webhook fallback
    n.send([Finding("k2", "also broken", "error")])
    assert len(sent) == 1


def test_deploy_renders_every_setting_it_is_given():
    """Every variable/secret passed to the 'Render agent.env' step must be written to agent.env.

    Guards against adding a setting to the step's env block but not to the loop, which silently
    drops it from the deployed config.
    """
    import pathlib
    import re
    wf = (pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
    step = wf.split("- name: Render agent.env", 1)[1].split("- name:", 1)[0]
    env_block, run_block = step.split("run: |", 1)
    given = set(re.findall(r"^\s+([A-Z_]+): \$\{\{ (?:vars|secrets)\.", env_block, re.M))
    loop = re.search(r"for v in (.*?); do", run_block, re.S).group(1)
    written = set(re.findall(r"[A-Z_]+", loop))
    assert given - written == set(), f"passed to the step but never written to agent.env: {sorted(given - written)}"


def test_client_approval_mode_runs_audited_and_fails_closed():
    from sonarr_agent.bus import Approvals, BusTool, schema
    events = []
    tool = BusTool("remove_queue_item", "remove", schema(), lambda queue_id: events.append(("ran", queue_id)) or "removed",
                   read_only=False)

    class Recorder(FakeOutbox):
        def send(self, msg):
            events.append(("notice", msg.title))
            return self.ok

    ap = Approvals("sonarr", [], mode="client")
    assert ap.handle(tool, {"queue_id": 1})["status"] == "refused" and events == []  # no audit channel: no action
    ap.outbox = Recorder([])
    out = ap.handle(tool, {"queue_id": 2})
    assert out == {"status": "done", "action": "remove_queue_item(queue_id=2)", "result": "removed"}
    assert [e[0] for e in events] == ["notice", "ran", "notice"]  # announced BEFORE it runs, result after
    assert ap.tools() == []  # no code tools in client mode
    events.clear()
    ap.outbox = Recorder([], ok=False)  # can't announce: refuse without running
    assert ap.handle(tool, {"queue_id": 3})["status"] == "refused" and ("ran", 3) not in events
    boom = BusTool("run_command", "x", schema(), lambda: 1 / 0, read_only=False)
    ap.outbox = Recorder([])
    with pytest.raises(ZeroDivisionError):
        ap.handle(boom, {})
    assert "failed" in events[-1][1]
    with pytest.raises(ValueError):
        Approvals("sonarr", [], mode="yolo")


# --- Hermes plugin (integrations/hermes/homelab-approvals) ---

def _load_plugin(tmp_path, monkeypatch, bus_url):
    import importlib.util
    import pathlib
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text("AGENT_BUS_TOKEN=s3cret\nAGENT_BUS_SERVERS=sonarr\n")
    (home / "config.yaml").write_text(
        f'mcp_servers:\n  sonarr:\n    url: "{bus_url}"\n    headers:\n      Authorization: "Bearer ${{AGENT_BUS_TOKEN}}"\n')
    monkeypatch.setenv("HERMES_HOME", str(home))
    path = pathlib.Path(__file__).resolve().parent.parent / "integrations" / "hermes" / "homelab-approvals" / "__init__.py"
    spec = importlib.util.spec_from_file_location("homelab_approvals_plugin", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_hermes_plugin_gates_only_destructive_agent_tools(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    from sonarr_agent.bus import Approvals, BusTool, Runtime, schema, serve_mcp
    tools = Runtime("sonarr").common_tools(check_is_destructive=True) + [
        BusTool("get_queue", "q", schema(), lambda: []),
        BusTool("remove_queue_item", "r", schema(), lambda **a: "x", read_only=False)]
    server = serve_mcp("127.0.0.1", 0, "s3cret", tools, "sonarr-agent", Approvals("sonarr", [], mode="client"))
    try:
        p = _load_plugin(tmp_path, monkeypatch, f"http://127.0.0.1:{server.server_address[1]}/mcp")
        assert p.pre_tool_call("mcp__sonarr__get_queue", {}) is None  # read-only: no prompt
        assert p.pre_tool_call("mcp__unraid__unraid_docker_restart", {"id": "plex"}) is None  # not watched here
        assert p.pre_tool_call("terminal", {"command": "ls"}) is None  # not an MCP tool
        d = p.pre_tool_call("mcp__sonarr__remove_queue_item", {"queue_id": 7, "blocklist": True})
        assert d["action"] == "approve" and "remove_queue_item(queue_id=7, blocklist=true)" in d["message"]
        d2 = p.pre_tool_call("mcp__sonarr__remove_queue_item", {"queue_id": 8, "blocklist": True})
        assert d["rule_key"] != d2["rule_key"]  # "Always" can't cover a different action
        assert p.pre_tool_call("mcp__sonarr__agent_run_check", {})["action"] == "approve"
    finally:
        server.shutdown()


def test_hermes_plugin_fails_closed_when_agent_unreachable(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    p = _load_plugin(tmp_path, monkeypatch, "http://127.0.0.1:9/mcp")
    d = p.pre_tool_call("mcp__sonarr__get_queue", {})
    assert d["action"] == "approve" and "every tool asks" in d["message"]


def test_hermes_plugin_asks_when_it_cannot_read_config(tmp_path, monkeypatch):
    # Hermes's runtime has no PyYAML; a missing reader once raised inside the hook instead of asking.
    p = _load_plugin(tmp_path, monkeypatch, "http://127.0.0.1:9/mcp")
    monkeypatch.setattr(p, "_load_config", lambda: (_ for _ in ()).throw(ImportError("No module named 'yaml'")))
    d = p.pre_tool_call("mcp__sonarr__get_queue", {})
    assert d["action"] == "approve" and "every tool asks" in d["message"]


def test_health_fails_when_a_loop_is_overdue_or_an_endpoint_is_down(tmp_path, monkeypatch):
    from sonarr_agent import health

    monkeypatch.setenv("HEALTH_DIR", str(tmp_path / "health"))
    assert health.check()[0] == ["nothing has checked in yet"]
    health.beat("main", 60)
    problems, fine = health.check()
    assert not problems and fine[0].startswith("main ran")
    health.beat("slow", -5)
    assert health.check()[0][0].startswith("slow: overdue by 5s")
    health.reset()
    health.beat("main", 60)
    health.endpoint("bus", "http://127.0.0.1:9/health")  # nothing listens on the discard port
    problems, _ = health.check(timeout=2)
    assert len(problems) == 1 and problems[0].startswith("bus: ")


def test_discord_posts_are_sent_under_the_agents_own_name(monkeypatch):
    from sonarr_agent import notice

    posted = []
    monkeypatch.setattr(notice, "_post_webhook", lambda url, payload: posted.append(payload) or True)
    url = "https://discord.com/api/webhooks/" + "1/fake-TOKEN"  # split so the public-sync secret scan passes
    assert notice.Outbox([url]).send(notice.Message("hi"))
    notice.Outbox([url], username="Someone else").send(notice.Message("hi"))
    assert [p["username"] for p in posted] == ["sonarr-agent", "Someone else"]
