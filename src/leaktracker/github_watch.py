"""Rate-limit-friendly GitHub public events watcher. Read-only. No key validation."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import requests

from .redact import safe_match_record, scrub_text
from .rules import scan_text
from .store import Store

EVENTS_URL = "https://api.github.com/events"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{sha}/{path}"
COMMIT_API = "https://api.github.com/repos/{repo}/commits/{sha}"


class GitHubWatcher:
    def __init__(
        self,
        store: Store,
        *,
        token: str | None = None,
        session: requests.Session | None = None,
        user_agent: str = "keyscout-leaktracker/0.1 (+local-mvp; read-only)",
    ):
        self.store = store
        self.token = token
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "User-Agent": user_agent,
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        self.poll_interval = int(self.store.get_meta("poll_interval") or "60")
        self.etag: str | None = self.store.get_meta("etag") or None
        self.last_event_id: str | None = self.store.get_meta("last_event_id") or None
        self._backoff = 0

    def _get(self, url: str, **kwargs) -> requests.Response:
        attempts = 0
        while True:
            attempts += 1
            r = self.session.get(url, timeout=30, **kwargs)
            if r.status_code in (403, 429) and (
                "rate limit" in (r.text or "").lower()
                or r.headers.get("X-RateLimit-Remaining") == "0"
                or r.status_code == 429
            ):
                reset = int(r.headers.get("X-RateLimit-Reset", "0") or 0)
                retry_after = int(r.headers.get("Retry-After", "0") or 0)
                wait = retry_after or (max(5, min(180, reset - int(time.time()))) if reset else 30)
                self._backoff = min(300, (self._backoff or 5) * 2)
                wait = max(wait, self._backoff)
                self.store.set_meta("backoff_until", str(int(time.time()) + wait))
                if attempts >= 3:
                    return r
                time.sleep(wait)
                continue
            if r.status_code >= 500 and attempts < 3:
                time.sleep(min(30, 2 ** attempts))
                continue
            self._backoff = 0
            return r

    def fetch_events(self) -> tuple[list[dict[str, Any]], int]:
        headers = {}
        if self.etag:
            headers["If-None-Match"] = self.etag
        r = self._get(EVENTS_URL, headers=headers)
        poll = int(r.headers.get("X-Poll-Interval", "60") or 60)
        self.poll_interval = max(30, poll)
        if r.status_code == 304:
            return [], self.poll_interval
        r.raise_for_status()
        if "ETag" in r.headers:
            self.etag = r.headers["ETag"]
            self.store.set_meta("etag", self.etag)
        remaining = r.headers.get("X-RateLimit-Remaining", "?")
        limit = r.headers.get("X-RateLimit-Limit", "?")
        self.store.set_meta("ratelimit", f"{remaining}/{limit}")
        self.store.set_meta("poll_interval", str(self.poll_interval))
        return r.json(), self.poll_interval

    def _push_commits(self, event: dict[str, Any]) -> Iterator[tuple[str, str, str]]:
        """Yield (repo, sha, source_type) for PushEvent commits.

        Note: as of 2026 the public Events API often omits payload.commits and
        only provides payload.head / before. We prefer head, then any commits[].
        """
        if event.get("type") != "PushEvent":
            return
        repo = (event.get("repo") or {}).get("name")
        if not repo:
            return
        payload = event.get("payload") or {}
        shas = []
        head = payload.get("head")
        if head:
            shas.append(head)
        for c in payload.get("commits") or []:
            sha = c.get("sha")
            if sha and sha not in shas:
                shas.append(sha)
        for sha in shas:
            yield repo, sha, "github_commit"

    def fetch_commit_patch(self, repo: str, sha: str) -> str:
        """Fetch commit message + patch text. Read-only."""
        url = COMMIT_API.format(repo=repo, sha=sha)
        r = self._get(url, headers={"Accept": "application/vnd.github.diff"})
        if r.status_code == 200 and r.text:
            # Prefer diff if available
            if "diff --git" in r.text or r.text.startswith("diff"):
                return r.text[:500_000]  # cap
        # Fallback JSON: messages + file patches
        r = self._get(url)
        if r.status_code != 200:
            return ""
        data = r.json()
        parts = [data.get("commit", {}).get("message") or ""]
        for f in data.get("files") or []:
            parts.append(f.get("filename") or "")
            parts.append(f.get("patch") or "")
        return "\n".join(parts)[:500_000]

    def process_text(
        self, text: str, *, source_type: str, public_locator: str, found_at: str | None = None
    ) -> int:
        """Scan text, store fingerprints only. Returns number of new findings."""
        inserted = 0
        for rule, raw in scan_text(text):
            rec = safe_match_record(raw, rule.provider, rule.id)
            # Drop raw immediately from local namespace intent (GC)
            del raw
            ok, fid = self.store.insert_finding(
                fingerprint=rec["fingerprint"],
                fingerprint_hmac=rec["fingerprint_hmac"],
                redacted=rec["redacted"],
                provider=rec["provider"],
                rule_id=rec["rule_id"],
                source_type=source_type,
                public_locator=public_locator,
                found_at=found_at,
            )
            if ok:
                inserted += 1
        return inserted

    def poll_once(self, *, max_commits: int = 15) -> dict[str, Any]:
        """One poll cycle. Caps commit fetches to stay rate-limit friendly."""
        events, interval = self.fetch_events()
        new_findings = 0
        commits_checked = 0
        events_seen = 0
        newest_id = self.last_event_id

        for ev in events:
            events_seen += 1
            eid = str(ev.get("id") or "")
            if newest_id is None and eid:
                newest_id = eid
            # Skip events we've already processed by id when possible
            if self.last_event_id and eid and int(eid) <= int(self.last_event_id):
                continue
            if newest_id is None or (eid and int(eid) > int(newest_id)):
                newest_id = eid

            created = (ev.get("created_at") or "").replace("+00:00", "Z")
            # Cheap pass: scan inline commit messages in the event payload (no extra API call)
            for repo, sha, stype in self._push_commits(ev):
                inline = ""
                for c in (ev.get("payload") or {}).get("commits") or []:
                    if c.get("sha") == sha:
                        inline = c.get("message") or ""
                        break
                if inline:
                    locator = f"https://github.com/{repo}/commit/{sha}"
                    new_findings += self.process_text(
                        inline, source_type=stype, public_locator=locator, found_at=created or None
                    )
            # Deeper pass: fetch a few commit patches (rate-limit capped)
            for repo, sha, stype in self._push_commits(ev):
                if commits_checked >= max_commits:
                    break
                locator = f"https://github.com/{repo}/commit/{sha}"
                try:
                    text = self.fetch_commit_patch(repo, sha)
                except Exception as e:
                    self.store.set_meta("last_error", scrub_text(str(e))[:500])
                    continue
                commits_checked += 1
                new_findings += self.process_text(
                    text, source_type=stype, public_locator=locator, found_at=created or None
                )
            if commits_checked >= max_commits:
                break

        if newest_id:
            self.last_event_id = newest_id
            self.store.set_meta("last_event_id", newest_id)
        self.store.set_meta("last_poll_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        return {
            "events_seen": events_seen,
            "commits_checked": commits_checked,
            "new_findings": new_findings,
            "poll_interval": interval,
            "ratelimit": self.store.get_meta("ratelimit"),
        }

    def run_for(self, seconds: float = 120, *, max_commits_per_poll: int = 10) -> dict[str, Any]:
        """Short live run. No notifications. Caps total wall time."""
        deadline = time.time() + seconds
        totals = {"polls": 0, "events_seen": 0, "commits_checked": 0, "new_findings": 0}
        while time.time() < deadline:
            stats = self.poll_once(max_commits=max_commits_per_poll)
            totals["polls"] += 1
            totals["events_seen"] += stats["events_seen"]
            totals["commits_checked"] += stats["commits_checked"]
            totals["new_findings"] += stats["new_findings"]
            totals["last"] = stats
            sleep_for = min(stats["poll_interval"], max(1, deadline - time.time()))
            if sleep_for <= 0:
                break
            time.sleep(sleep_for)
        return totals
