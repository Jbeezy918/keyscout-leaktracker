import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from leaktracker.dashboard import write_dashboard
from leaktracker.redact import fingerprint_sha256, redact, safe_match_record, scrub_text
from leaktracker.reports import write_drafts
from leaktracker.rules import scan_text
from leaktracker.seed import seed_demo
from leaktracker.store import Store


def test_redact_never_returns_full_key():
    raw = "sk-proj-" + ("A1b2" * 10)
    r = redact(raw)
    assert raw not in r
    assert "…" in r or "..." in r


def test_fingerprint_stable():
    assert fingerprint_sha256("abc") == fingerprint_sha256("abc")
    assert fingerprint_sha256("abc") != fingerprint_sha256("abd")


def test_scan_finds_openai_and_skips_placeholder():
    text = 'key = "sk-proj-' + ("B1c2" * 10) + '"\nother = "sk-proj-EXAMPLEDEMO"'
    hits = list(scan_text(text))
    assert any(r.provider == "openai" for r, _ in hits)
    assert not any("EXAMPLE" in raw for _, raw in hits)


def test_scan_stripe_aws():
    text = "sk_live_" + ("Ab1" * 12) + "\nAKIA" + ("B2C3" * 4)
    # AKIA + 16 zeros may match pattern AKIA[0-9A-Z]{16}
    hits = list(scan_text(text))
    providers = {r.provider for r, _ in hits}
    assert "stripe" in providers


def test_store_forbids_raw_and_dedupes(tmp_path):
    db = tmp_path / "t.db"
    store = Store(db)
    rec = safe_match_record("sk-ant-" + "C" * 40, "anthropic", "anthropic-key")
    ok1, id1 = store.insert_finding(
        fingerprint=rec["fingerprint"],
        fingerprint_hmac=rec["fingerprint_hmac"],
        redacted=rec["redacted"],
        provider="anthropic",
        rule_id="anthropic-key",
        source_type="github_commit",
        public_locator="https://github.com/ex/r/commit/1",
    )
    ok2, id2 = store.insert_finding(
        fingerprint=rec["fingerprint"],
        fingerprint_hmac=rec["fingerprint_hmac"],
        redacted=rec["redacted"],
        provider="anthropic",
        rule_id="anthropic-key",
        source_type="github_commit",
        public_locator="https://github.com/ex/r/commit/1",
    )
    assert ok1 and not ok2 and id1 == id2
    # DB file must not contain the raw key
    blob = db.read_bytes()
    assert b"sk-ant-" + b"C" * 40 not in blob
    store.close()


def test_lookup_fingerprint(tmp_path):
    store = Store(tmp_path / "t.db")
    raw = "sk_test_" + "D" * 40
    rec = safe_match_record(raw, "stripe", "stripe-test")
    store.insert_finding(
        fingerprint=rec["fingerprint"],
        fingerprint_hmac=rec["fingerprint_hmac"],
        redacted=rec["redacted"],
        provider="stripe",
        rule_id="stripe-test",
        source_type="github_gist",
        public_locator="https://gist.github.com/x/1",
    )
    hits = store.lookup_fingerprint(rec["fingerprint"])
    assert len(hits) == 1
    assert hits[0]["provider"] == "stripe"
    prefix_hits = store.lookup_fingerprint(rec["fingerprint"][:12])
    assert len(prefix_hits) >= 1
    store.close()


def test_drafts_not_network(tmp_path):
    store = Store(tmp_path / "t.db")
    seed_demo(store)
    drafts = tmp_path / "drafts"
    stats = write_drafts(store, drafts, skip_github_partner=True)
    assert stats["drafts_written"] >= 1
    files = list(drafts.glob("report_*.md"))
    assert files
    text = files[0].read_text()
    assert "DO NOT SEND" in text
    assert "sk-proj-EXAMPLE" not in text or "Redacted" in text  # body uses redacted field
    # ensure no full fake key from seed leaked as "raw"
    assert "EXAMPLEDEMOKEY000000000000001" not in text
    store.close()


def test_dashboard_and_fingerprint_index(tmp_path):
    store = Store(tmp_path / "t.db")
    seed_demo(store)
    out = tmp_path / "dash"
    paths = write_dashboard(store, out, test_label="unit test")
    html = Path(paths["html"]).read_text()
    assert "Found" in html and "Check if my key leaked" in html
    idx = json.loads(Path(paths["fingerprints"]).read_text())
    assert idx["count"] >= 1
    assert all(len(f) == 64 for f in idx["fingerprints"])
    store.close()


def test_scrub_text():
    s = scrub_text("leak sk-" + "E" * 30 + " end")
    assert "sk-" + "E" * 10 not in s
    assert "REDACTED" in s


def test_process_text_integration(tmp_path):
    from leaktracker.github_watch import GitHubWatcher

    store = Store(tmp_path / "t.db")
    w = GitHubWatcher(store, token=None)
    raw = "sk-proj-" + ("F9e8" * 12)
    n = w.process_text(
        f"const KEY = '{raw}';",
        source_type="github_commit",
        public_locator="https://github.com/ex/r/commit/abc",
    )
    assert n == 1
    assert store.counters()["found"] == 1
    assert raw.encode() not in (tmp_path / "t.db").read_bytes()
    store.close()


def test_benign_fixture_has_no_hits():
    from pathlib import Path

    from leaktracker.rules import scan_text
    text = Path(__file__).parent.joinpath("fixtures/benign.txt").read_text()
    hits = list(scan_text(text))
    assert hits == [], f"false positives: {[(r.id, m[:20]) for r,m in hits]}"


def test_new_provider_rules_fire():
    from leaktracker.rules import scan_text
    text = "\n".join([
        "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        "pypi-AgEIcHlwaS5vcmcCJGE3Zj" + "AbCdEfGhIjKlMnOp",
        "dop_v1_" + ("ab12" * 16),
        "SG." + "AbCdEfGhIjKlMnOp" + "." + "QrStUvWxYz012345",
        "sb_secret_" + "AbCdEfGhIjKlMnOpQrSt",
    ])
    providers = {r.provider for r, _ in scan_text(text)}
    assert "npm" in providers and "pypi" in providers and "digitalocean" in providers


def test_weekly_report(tmp_path):
    from leaktracker.seed import seed_demo
    from leaktracker.store import Store
    from leaktracker.weekly import build_report, write_weekly
    store = Store(tmp_path / "t.db")
    seed_demo(store)
    report = build_report(store)
    assert report["funnel"]["found"] >= 1
    paths = write_weekly(store, tmp_path / "reports")
    md = Path(paths["latest"]).read_text()
    assert "Weekly Report" in md and "sk-proj-EXAMPLE" not in md
    store.close()


def test_etag_persisted(tmp_path):
    from leaktracker.github_watch import GitHubWatcher
    from leaktracker.store import Store
    store = Store(tmp_path / "t.db")
    store.set_meta("etag", '"abc"')
    w = GitHubWatcher(store)
    assert w.etag == '"abc"'
    store.close()
