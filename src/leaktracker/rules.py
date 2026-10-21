"""Gitleaks/TruffleHog-style detection rules. Pattern match only — never validate."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    provider: str
    description: str
    pattern: re.Pattern
    min_len: int = 16


# Conservative prefix rules only (low false positives). No bare entropy guesses.
RULES: list[Rule] = [
    Rule("openai-sk", "openai", "OpenAI API key",
         re.compile(r"\b(sk-[A-Za-z0-9]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?)\b"), 20),
    Rule("openai-sk-proj", "openai", "OpenAI project API key",
         re.compile(r"\b(sk-proj-[A-Za-z0-9_-]{20,})\b"), 28),
    Rule("anthropic-key", "anthropic", "Anthropic API key",
         re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"), 28),
    Rule("stripe-live", "stripe", "Stripe live secret key",
         re.compile(r"\b(sk_live_[A-Za-z0-9]{20,})\b"), 28),
    Rule("stripe-test", "stripe", "Stripe test secret key",
         re.compile(r"\b(sk_test_[A-Za-z0-9]{20,})\b"), 28),
    Rule("stripe-rk", "stripe", "Stripe restricted key",
         re.compile(r"\b(rk_live_[A-Za-z0-9]{20,})\b"), 28),
    Rule("aws-access-key", "aws", "AWS access key id",
         re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 20),
    Rule("aws-asio", "aws", "AWS ASIA temporary key id",
         re.compile(r"\b(ASIA[0-9A-Z]{16})\b"), 20),
    Rule("google-api-key", "google", "Google API key",
         re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 39),
    Rule("github-pat", "github", "GitHub personal access token",
         re.compile(r"\b(ghp_[A-Za-z0-9]{36,})\b"), 40),
    Rule("github-finegrained", "github", "GitHub fine-grained PAT",
         re.compile(r"\b(github_pat_[A-Za-z0-9_]{20,})\b"), 30),
    Rule("github-oauth", "github", "GitHub OAuth access token",
         re.compile(r"\b(gho_[A-Za-z0-9]{36,})\b"), 40),
    Rule("github-user", "github", "GitHub user-to-server token",
         re.compile(r"\b(ghu_[A-Za-z0-9]{36,})\b"), 40),
    Rule("github-server", "github", "GitHub server-to-server token",
         re.compile(r"\b(ghs_[A-Za-z0-9]{36,})\b"), 40),
    Rule("slack-token", "slack", "Slack token",
         re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), 20),
    Rule("huggingface", "huggingface", "Hugging Face token",
         re.compile(r"\b(hf_[A-Za-z0-9]{30,})\b"), 34),
    Rule("sendgrid", "sendgrid", "SendGrid API key",
         re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b"), 30),
    Rule("twilio", "twilio", "Twilio account SID (paired with auth elsewhere)",
         re.compile(r"\b(AC[0-9a-f]{32})\b"), 34),
    Rule("npm-token", "npm", "npm access token",
         re.compile(r"\b(npm_[A-Za-z0-9]{36,})\b"), 40),
    Rule("pypi-token", "pypi", "PyPI API token",
         re.compile(r"\b(pypi-[A-Za-z0-9_-]{20,})\b"), 30),
    Rule("digitalocean", "digitalocean", "DigitalOcean personal token",
         re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"), 70),
    Rule("supabase", "supabase", "Supabase service role JWT-like key",
         re.compile(r"\b(sb_secret_[A-Za-z0-9_-]{20,})\b"), 30),
    Rule("telegram", "telegram", "Telegram bot token",
         re.compile(r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b"), 40),
]

PLACEHOLDER_SUBSTR = (
    "example", "your_key", "your-key", "placeholder", "redacted",
    "changeme", "dummy", "xxxx", "todo", "fixkey", "sample",
)


def _is_placeholder(raw: str) -> bool:
    low = raw.lower()
    if any(p in low for p in PLACEHOLDER_SUBSTR):
        return True
    # Strip common prefixes then check filler
    body = raw
    for pref in ("sk_live_", "sk_test_", "rk_live_", "sk-proj-", "sk-ant-", "sk-",
                 "ghp_", "gho_", "ghu_", "ghs_", "github_pat_", "hf_", "npm_",
                 "pypi-", "dop_v1_", "sb_secret_", "AKIA", "ASIA", "AIza", "AC", "SG."):
        if body.startswith(pref) or body.lower().startswith(pref.lower()):
            body = body[len(pref):]
            break
    else:
        body = raw.split("_")[-1] if "_" in raw else raw
    bl = body.lower().replace("-", "").replace(".", "")
    if len(bl) >= 16 and len(set(bl)) == 1:
        return True
    if len(bl) >= 16 and set(bl) <= set("0x"):
        return True
    return False


def scan_text(text: str) -> Iterator[tuple[Rule, str]]:
    """Yield (rule, raw_match). Caller must fingerprint/redact and discard raw_match."""
    if not text:
        return
    seen = set()
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            raw = m.group(1)
            if len(raw) < rule.min_len:
                continue
            if _is_placeholder(raw):
                continue
            key = (rule.id, raw)
            if key in seen:
                continue
            seen.add(key)
            yield rule, raw


def provider_for_rule(rule_id: str) -> str | None:
    for r in RULES:
        if r.id == rule_id:
            return r.provider
    return None
