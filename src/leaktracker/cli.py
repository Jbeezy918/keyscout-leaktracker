"""CLI entrypoints for Leak Tracker MVP."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running without install
ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from leaktracker.dashboard import write_dashboard
from leaktracker.github_watch import GitHubWatcher
from leaktracker.recheck import Rechecker
from leaktracker.redact import fingerprint_sha256
from leaktracker.weekly import write_weekly
from leaktracker.reports import write_drafts
from leaktracker.seed import seed_demo
from leaktracker.store import Store


def default_paths():
    data = Path(os.environ.get("LEAKTRACKER_DATA", ROOT / "data"))
    return {
        "db": data / "leaktracker.db",
        "dashboard": Path(os.environ.get("LEAKTRACKER_DASHBOARD", ROOT / "dashboard" / "public")),
        "drafts": Path(os.environ.get("LEAKTRACKER_DRAFTS", ROOT / "drafts" / "reports")),
    }


def cmd_seed(args):
    p = default_paths()
    store = Store(p["db"])
    n = seed_demo(store)
    print(json.dumps({"seeded": n, "counters": store.counters()}))
    store.close()


def cmd_watch(args):
    p = default_paths()
    store = Store(p["db"])
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    w = GitHubWatcher(store, token=token)
    if args.once:
        stats = w.poll_once(max_commits=args.max_commits)
    else:
        stats = w.run_for(args.seconds, max_commits_per_poll=args.max_commits)
    print(json.dumps({"watch": stats, "counters": store.counters()}, indent=2))
    store.close()


def cmd_recheck(args):
    p = default_paths()
    store = Store(p["db"])
    stats = Rechecker(store).run(limit=args.limit)
    print(json.dumps({"recheck": stats, "counters": store.counters()}, indent=2))
    store.close()


def cmd_drafts(args):
    p = default_paths()
    store = Store(p["db"])
    stats = write_drafts(store, p["drafts"], limit=args.limit, skip_github_partner=not args.include_partner)
    print(json.dumps({"drafts": stats, "counters": store.counters()}, indent=2))
    store.close()


def cmd_dashboard(args):
    p = default_paths()
    store = Store(p["db"])
    paths = write_dashboard(store, p["dashboard"], test_label=args.label)
    print(json.dumps({"dashboard": paths, "counters": store.counters()}, indent=2))
    store.close()


def cmd_weekly(args):
    p = default_paths()
    store = Store(p["db"])
    out = Path(os.environ.get("LEAKTRACKER_REPORTS", ROOT / "dashboard" / "reports"))
    paths = write_weekly(store, out)
    print(json.dumps({"weekly": paths, "counters": store.counters()}, indent=2))
    store.close()


def cmd_check(args):
    p = default_paths()
    store = Store(p["db"])
    raw = args.fingerprint
    if args.key_file:
        # Read key from file for CLI check, hash, do not print key
        key = Path(args.key_file).read_text(encoding="utf-8").strip()
        raw = fingerprint_sha256(key)
        del key
    hits = store.lookup_fingerprint(raw)
    print(json.dumps({"fingerprint": raw[:16] + "…", "hits": hits}, indent=2))
    store.close()


def cmd_all(args):
    """seed (optional) → short watch → drafts → recheck → dashboard."""
    p = default_paths()
    store = Store(p["db"])
    if args.seed:
        seed_demo(store)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    w = GitHubWatcher(store, token=token)
    watch_stats = w.run_for(args.seconds, max_commits_per_poll=args.max_commits) if args.seconds > 0 else {"skipped": True}
    draft_stats = write_drafts(store, p["drafts"], skip_github_partner=True)
    recheck_stats = Rechecker(store).run(limit=20)
    weekly_paths = write_weekly(store, Path(os.environ.get("LEAKTRACKER_REPORTS", ROOT / "dashboard" / "reports")))
    dash = write_dashboard(
        store,
        p["dashboard"],
        test_label=args.label or "short test run (read-only; drafts not sent)",
    )
    out = {
        "watch": watch_stats,
        "drafts": draft_stats,
        "recheck": recheck_stats,
        "dashboard": dash,
        "weekly": weekly_paths,
        "counters": store.counters(),
        "by_source_provider": store.by_source_provider(),
    }
    print(json.dumps(out, indent=2))
    store.close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="leaktracker", description="KeyScout Leak Tracker MVP")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("seed", help="Insert synthetic demo findings")
    p.set_defaults(func=cmd_seed)

    p = sub.add_parser("watch", help="Poll GitHub public events (read-only)")
    p.add_argument("--once", action="store_true")
    p.add_argument("--seconds", type=float, default=90)
    p.add_argument("--max-commits", type=int, default=10)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("recheck", help="Re-fetch public locators")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_recheck)

    p = sub.add_parser("drafts", help="Write provider report drafts (NOT sent)")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--include-partner", action="store_true", help="Also draft non-deferred partner cases")
    p.set_defaults(func=cmd_drafts)

    p = sub.add_parser("dashboard", help="Write static HTML dashboard")
    p.add_argument("--label", default="")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("weekly", help="Write weekly aggregate report (no raw keys)")
    p.set_defaults(func=cmd_weekly)

    p = sub.add_parser("check", help="Lookup a fingerprint")
    p.add_argument("fingerprint", nargs="?", default="")
    p.add_argument("--key-file", help="File containing a key to hash (key not printed)")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("all", help="Short pipeline for local/NUC test")
    p.add_argument("--seed", action="store_true", help="Include synthetic demo rows")
    p.add_argument("--seconds", type=float, default=90)
    p.add_argument("--max-commits", type=int, default=8)
    p.add_argument("--label", default="")
    p.set_defaults(func=cmd_all)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
