"""Weekly public leak report generator (aggregates only — no raw keys)."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .store import Store, utcnow


def _parse(ts: str) -> datetime:
    try:
        return datetime.strptime(ts.replace("Z", ""), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def week_window(end: datetime | None = None) -> tuple[datetime, datetime]:
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    return start, end


def build_report(store: Store, *, end: datetime | None = None) -> dict[str, Any]:
    start, end = week_window(end)
    rows = store.conn.execute("SELECT * FROM findings").fetchall()
    by: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    funnel = {"found": 0, "reported": 0, "removed": 0, "confirmed": 0}
    for r in rows:
        found_at = _parse(r["found_at"])
        if not (start <= found_at <= end):
            continue
        by[r["source_type"]][r["provider"]] += 1
        funnel["found"] += 1
        if r["status_reported"]:
            funnel["reported"] += 1
        if r["status_removed"]:
            funnel["removed"] += 1
        if r["status_confirmed"]:
            funnel["confirmed"] += 1
    providers = sorted({p for s in by.values() for p in s}) or ["openai"]
    sources = sorted(by.keys()) or ["github_commit"]
    table: list[dict[str, Any]] = []
    for s in sources:
        row = {"source_type": s, **{p: by[s].get(p, 0) for p in providers}}
        row["total"] = sum(by[s].get(p, 0) for p in providers)
        table.append(row)
    return {
        "title": "KeyScout Leak Radar — Weekly Report",
        "period_start": start.strftime("%Y-%m-%d"),
        "period_end": end.strftime("%Y-%m-%d"),
        "generated_at": utcnow(),
        "providers": providers,
        "table": table,
        "funnel": funnel,
        "note": "Counts are pattern matches on public sources. We never validate or revoke keys.",
    }


def render_markdown(report: dict[str, Any]) -> str:
    providers = report["providers"]
    hdr = "| Source | " + " | ".join(providers) + " | Total |"
    sep = "|---|---:" + "|---:" * len(providers) + "|"
    lines = [
        f"# {report['title']}",
        "",
        f"Period: **{report['period_start']} → {report['period_end']}** (generated {report['generated_at']})",
        "",
        report["note"],
        "",
        hdr,
        sep,
    ]
    for row in report["table"]:
        cells = " | ".join(str(row.get(p, 0)) for p in providers)
        lines.append(f"| `{row['source_type']}` | {cells} | **{row['total']}** |")
    f = report["funnel"]
    lines += [
        "",
        f"**Status funnel:** Found {f['found']} → Reported (drafts) {f['reported']} "
        f"→ Removed from source {f['removed']} → Provider confirmed {f['confirmed']}.",
        "",
        "*Provider confirmed stays rare unless a human marks it.*",
    ]
    return "\n".join(lines) + "\n"


def write_weekly(store: Store, out_dir: Path, *, end: datetime | None = None) -> dict[str, str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(store, end=end)
    start = report["period_start"]
    md_path = out_dir / f"weekly_{start}.md"
    json_path = out_dir / f"weekly_{start}.json"
    latest_md = out_dir / "weekly_latest.md"
    md = render_markdown(report)
    md_path.write_text(md, encoding="utf-8")
    latest_md.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {"markdown": str(md_path), "json": str(json_path), "latest": str(latest_md)}
