"""Thin client for the Sonarr v4 API (/api/v3)."""

from __future__ import annotations

import time
from typing import Any

import requests


class SonarrError(RuntimeError):
    pass


class Sonarr:
    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0):
        self.base = base_url.rstrip("/") + "/api/v3"
        self.session = requests.Session()
        self.session.headers.update({"X-Api-Key": api_key, "Accept": "application/json"})
        self.timeout = timeout

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        resp = self.session.request(method, self.base + path, timeout=self.timeout, **kw)
        if resp.status_code >= 400:
            raise SonarrError(f"{method} {path} -> {resp.status_code}: {resp.text[:500]}")
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # --- read ---

    def status(self) -> dict:
        return self._req("GET", "/system/status")

    def health(self) -> list[dict]:
        return self._req("GET", "/health") or []

    def queue(self) -> list[dict]:
        records: list[dict] = []
        page = 1
        while True:
            data = self._req(
                "GET",
                "/queue",
                params={
                    "page": page,
                    "pageSize": 200,
                    "includeUnknownSeriesItems": "true",
                    "includeSeries": "true",
                    "includeEpisode": "true",
                },
            )
            batch = data.get("records", [])
            records.extend(batch)
            if not batch or len(records) >= data.get("totalRecords", 0):
                return records
            page += 1

    def import_lists(self) -> list[dict]:
        return self._req("GET", "/importlist") or []

    def import_list(self, list_id: int) -> dict:
        return self._req("GET", f"/importlist/{list_id}")

    def manual_import_candidates(self, download_id: str) -> list[dict]:
        return self._req(
            "GET", "/manualimport", params={"downloadId": download_id, "filterExistingFiles": "true"}
        ) or []

    def logs(self, level: str = "error", count: int = 50) -> list[dict]:
        data = self._req(
            "GET",
            "/log",
            params={"page": 1, "pageSize": count, "sortKey": "time", "sortDirection": "descending", "level": level},
        )
        return data.get("records", []) if isinstance(data, dict) else []

    def disk_space(self) -> list[dict]:
        return self._req("GET", "/diskspace") or []

    def download_clients(self) -> list[dict]:
        return self._req("GET", "/downloadclient") or []

    def remote_path_mappings(self) -> list[dict]:
        return self._req("GET", "/remotepathmapping") or []

    def root_folders(self) -> list[dict]:
        return self._req("GET", "/rootfolder") or []

    def test_import_list(self, resource: dict) -> tuple[bool, list[str]]:
        """Run Sonarr's provider test. Returns (ok, failure messages)."""
        resp = self.session.post(self.base + "/importlist/test", json=resource, timeout=self.timeout)
        if resp.status_code < 400:
            return True, []
        try:
            body = resp.json()
            msgs = [e.get("errorMessage", str(e)) for e in body] if isinstance(body, list) else [str(body)]
        except ValueError:
            msgs = [resp.text[:300]]
        return False, msgs

    # --- write ---

    def update_import_list(self, resource: dict, force: bool = True) -> dict:
        return self._req(
            "PUT", f"/importlist/{resource['id']}", params={"forceSave": str(force).lower()}, json=resource
        )

    def command(self, name: str, **body: Any) -> dict:
        return self._req("POST", "/command", json={"name": name, **body})

    def wait_command(self, command_id: int, timeout: float = 180.0) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            cmd = self._req("GET", f"/command/{command_id}")
            if cmd.get("status") in {"completed", "failed", "aborted", "cancelled", "orphaned"}:
                return cmd
            if time.monotonic() > deadline:
                return cmd
            time.sleep(3)

    def remove_queue_item(
        self, queue_id: int, *, remove_from_client: bool, blocklist: bool, skip_redownload: bool
    ) -> None:
        self._req(
            "DELETE",
            f"/queue/{queue_id}",
            params={
                "removeFromClient": str(remove_from_client).lower(),
                "blocklist": str(blocklist).lower(),
                "skipRedownload": str(skip_redownload).lower(),
            },
        )

    def manual_import(self, files: list[dict], import_mode: str = "auto") -> dict:
        return self.command("ManualImport", files=files, importMode=import_mode)


def field_value(resource: dict, name: str) -> Any:
    for f in resource.get("fields", []):
        if f.get("name") == name:
            return f.get("value")
    return None


def set_field(resource: dict, name: str, value: Any) -> None:
    for f in resource.get("fields", []):
        if f.get("name") == name:
            f["value"] = value
            return
    resource.setdefault("fields", []).append({"name": name, "value": value})
