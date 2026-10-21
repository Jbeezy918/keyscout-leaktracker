"""SQLite store. Schema forbids a raw_key column; only fingerprints + redactions."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT NOT NULL,
  fingerprint_hmac TEXT NOT NULL,
  redacted TEXT NOT NULL,
  provider TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  public_locator TEXT NOT NULL,
  found_at TEXT NOT NULL,
  status_found INTEGER NOT NULL DEFAULT 1,
  status_reported INTEGER NOT NULL DEFAULT 0,
  status_removed INTEGER NOT NULL DEFAULT 0,
  status_confirmed INTEGER NOT NULL DEFAULT 0,
  reported_at TEXT,
  removed_at TEXT,
  confirmed_at TEXT,
  report_draft_path TEXT,
  github_partner_likely INTEGER NOT NULL DEFAULT 0,
  last_recheck_at TEXT,
  UNIQUE(fingerprint, public_locator)
);

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source_type);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
"""

# Providers already in GitHub secret scanning partner program (approximate; for dedupe notes)
GITHUB_PARTNER_PROVIDERS = frozenset(
    {"openai", "anthropic", "stripe", "aws", "google", "slack", "huggingface"}
)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._assert_no_raw_key_column()

    def _assert_no_raw_key_column(self) -> None:
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(findings)")}
        forbidden = {"raw_key", "token", "secret", "api_key", "key"}
        if cols & forbidden:
            raise RuntimeError(f"Forbidden columns present: {cols & forbidden}")

    def close(self) -> None:
        self.conn.close()

    def insert_finding(
        self,
        *,
        fingerprint: str,
        fingerprint_hmac: str,
        redacted: str,
        provider: str,
        rule_id: str,
        source_type: str,
        public_locator: str,
        found_at: str | None = None,
    ) -> tuple[bool, int | None]:
        """Insert if new. Returns (inserted, id)."""
        found_at = found_at or utcnow()
        partner = 1 if provider in GITHUB_PARTNER_PROVIDERS and source_type.startswith("github") else 0
        try:
            cur = self.conn.execute(
                """INSERT INTO findings
                (fingerprint, fingerprint_hmac, redacted, provider, rule_id,
                 source_type, public_locator, found_at, github_partner_likely)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    fingerprint,
                    fingerprint_hmac,
                    redacted,
                    provider,
                    rule_id,
                    source_type,
                    public_locator,
                    found_at,
                    partner,
                ),
            )
            self.conn.commit()
            return True, cur.lastrowid
        except sqlite3.IntegrityError:
            row = self.conn.execute(
                "SELECT id FROM findings WHERE fingerprint=? AND public_locator=?",
                (fingerprint, public_locator),
            ).fetchone()
            return False, int(row["id"]) if row else None

    def mark_reported(self, finding_id: int, draft_path: str) -> None:
        self.conn.execute(
            """UPDATE findings SET status_reported=1, reported_at=?, report_draft_path=?
               WHERE id=?""",
            (utcnow(), draft_path, finding_id),
        )
        self.conn.commit()

    def mark_removed(self, finding_id: int, removed: bool) -> None:
        if removed:
            self.conn.execute(
                """UPDATE findings SET status_removed=1, removed_at=?, last_recheck_at=?
                   WHERE id=?""",
                (utcnow(), utcnow(), finding_id),
            )
        else:
            self.conn.execute(
                "UPDATE findings SET last_recheck_at=? WHERE id=?",
                (utcnow(), finding_id),
            )
        self.conn.commit()

    def mark_confirmed(self, finding_id: int) -> None:
        self.conn.execute(
            """UPDATE findings SET status_confirmed=1, confirmed_at=? WHERE id=?""",
            (utcnow(), finding_id),
        )
        self.conn.commit()

    def pending_recheck(self, limit: int = 50) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """SELECT * FROM findings WHERE status_removed=0
                   ORDER BY COALESCE(last_recheck_at,'') ASC, id ASC LIMIT ?""",
                (limit,),
            )
        )

    def all_fingerprints(self) -> list[str]:
        return [r["fingerprint"] for r in self.conn.execute("SELECT DISTINCT fingerprint FROM findings")]

    def lookup_fingerprint(self, fp: str) -> list[dict[str, Any]]:
        fp = fp.strip().lower()
        rows = self.conn.execute(
            """SELECT redacted, provider, source_type, public_locator, found_at,
                      status_reported, status_removed, status_confirmed
               FROM findings WHERE fingerprint=? OR fingerprint LIKE ?""",
            (fp, fp + "%") if len(fp) >= 16 else (fp, fp),  # prefix only if long enough
        ).fetchall() if len(fp) >= 16 else self.conn.execute(
            "SELECT redacted, provider, source_type, public_locator, found_at, status_reported, status_removed, status_confirmed FROM findings WHERE fingerprint=?",
            (fp,),
        ).fetchall()
        # For short prefixes (k-anon style), require >= 10 hex chars
        if len(fp) < 64 and len(fp) >= 10:
            rows = self.conn.execute(
                """SELECT redacted, provider, source_type, public_locator, found_at,
                          status_reported, status_removed, status_confirmed
                   FROM findings WHERE fingerprint LIKE ?""",
                (fp + "%",),
            ).fetchall()
        return [dict(r) for r in rows]

    def counters(self) -> dict[str, int]:
        def c(where: str = "1=1") -> int:
            return int(self.conn.execute(f"SELECT COUNT(*) AS n FROM findings WHERE {where}").fetchone()["n"])

        return {
            "found": c(),
            "reported": c("status_reported=1"),
            "removed": c("status_removed=1"),
            "confirmed": c("status_confirmed=1"),
            "found_24h": c("found_at >= datetime('now','-1 day')"),
            "found_30d": c("found_at >= datetime('now','-30 day')"),
        }

    def by_source_provider(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT source_type, provider, COUNT(*) AS n FROM findings
               GROUP BY source_type, provider ORDER BY n DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    def recent(self, limit: int = 25) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT id, redacted, provider, rule_id, source_type, public_locator, found_at,
                      status_reported, status_removed, status_confirmed, github_partner_likely
               FROM findings ORDER BY found_at DESC, id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def export_fingerprint_index(self) -> dict[str, Any]:
        """Public check index: full SHA-256 hex only (no keys, no locators that embed secrets)."""
        fps = sorted(set(self.all_fingerprints()))
        return {
            "version": 1,
            "algo": "sha256",
            "note": "Hash your key locally: sha256(key).hexdigest(), then search. Never send the raw key.",
            "count": len(fps),
            "fingerprints": fps,
        }

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default
