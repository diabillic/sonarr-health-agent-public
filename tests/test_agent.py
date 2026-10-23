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
