"""Synthetic findings for tests/demo. Uses fake key-shaped strings that are not real credentials."""

from __future__ import annotations

from .redact import safe_match_record
from .store import Store

# Clearly fake payloads — contain 'EXAMPLE' so live rules would skip them;
# we insert via safe_match_record directly for dashboard demos.
FAKE = [
    ("openai", "openai-sk-proj", "sk-proj-" + "EXAMPLEDEMOKEY000000000000001", "github_commit", "https://github.com/example/demo/commit/aaa111"),
    ("anthropic", "anthropic-key", "sk-ant-" + "EXAMPLEDEMOKEY00000000000002", "github_commit", "https://github.com/example/demo/commit/bbb222"),
    ("stripe", "stripe-test", "sk_test_" + "EXAMPLEDEMOKEY000000000003", "github_gist", "https://gist.github.com/example/ccc333"),
    ("aws", "aws-access-key", "AKIA" + "EXAMPLEDEMOKEY0", "github_commit", "https://github.com/example/demo/commit/ddd444"),
    ("google", "google-api-key", "AIza" + "EXAMPLEDEMOKEY000000000000000001", "github_commit", "https://github.com/example/demo/commit/eee555"),
]


def seed_demo(store: Store) -> int:
    n = 0
    for provider, rule_id, raw, source, locator in FAKE:
        rec = safe_match_record(raw, provider, rule_id)
        ok, _ = store.insert_finding(
            fingerprint=rec["fingerprint"],
            fingerprint_hmac=rec["fingerprint_hmac"],
            redacted=rec["redacted"],
            provider=provider,
            rule_id=rule_id,
            source_type=source,
            public_locator=locator,
        )
        if ok:
            n += 1
    return n
