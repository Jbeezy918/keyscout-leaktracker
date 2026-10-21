"""Re-check whether the public locator still contains a matching pattern.

Important: we re-scan the public page for *any* match of the same provider/rule
pattern family, comparing fingerprints of matches found. We never call provider
APIs to validate keys.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from .redact import fingerprint_sha256, scrub_text
from .rules import scan_text
from .store import Store


class Rechecker:
    def __init__(self, store: Store, session: requests.Session | None = None):
        self.store = store
        self.session = session or requests.Session()
        self.session.headers.update(
            {"User-Agent": "keyscout-leaktracker/0.1 (+recheck; read-only)", "Accept": "text/plain,text/html,*/*"}
        )

    def fetch_locator(self, locator: str) -> str:
        """Fetch public content for a github commit URL or raw URL."""
        u = urlparse(locator)
        if "github.com" in (u.netloc or "") and "/commit/" in (u.path or ""):
            # https://github.com/owner/repo/commit/sha -> API diff
            parts = [p for p in u.path.split("/") if p]
            # owner, repo, commit, sha
            if len(parts) >= 4 and parts[2] == "commit":
                owner, repo, sha = parts[0], parts[1], parts[3]
                api = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
                r = self.session.get(
                    api, headers={"Accept": "application/vnd.github.diff"}, timeout=30
                )
                if r.status_code == 200 and r.text:
                    return r.text[:500_000]
                r = self.session.get(api, timeout=30)
                if r.status_code == 200:
                    data = r.json()
                    chunks = [data.get("commit", {}).get("message") or ""]
                    for f in data.get("files") or []:
                        chunks.append(f.get("patch") or "")
                    return "\n".join(chunks)[:500_000]
        r = self.session.get(locator, timeout=30)
        if r.status_code == 404:
            return ""  # gone entirely
        r.raise_for_status()
        return (r.text or "")[:500_000]

    def still_present(self, fingerprint: str, locator: str) -> bool:
        text = self.fetch_locator(locator)
        if not text:
            return False
        for rule, raw in scan_text(text):
            fp = fingerprint_sha256(raw)
            del raw
            if fp == fingerprint:
                return True
        return False

    def run(self, limit: int = 20) -> dict[str, int]:
        rows = self.store.pending_recheck(limit=limit)
        checked = 0
        removed = 0
        errors = 0
        for row in rows:
            try:
                present = self.still_present(row["fingerprint"], row["public_locator"])
                self.store.mark_removed(int(row["id"]), removed=not present)
                checked += 1
                if not present:
                    removed += 1
            except Exception as e:
                errors += 1
                self.store.set_meta("last_recheck_error", scrub_text(str(e))[:500])
        return {"checked": checked, "newly_removed": removed, "errors": errors}
