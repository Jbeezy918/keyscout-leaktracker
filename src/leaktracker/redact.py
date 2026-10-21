"""Redaction and fingerprinting. Raw keys must never leave this module onto disk."""

from __future__ import annotations

import hashlib
import hmac
import os
import re


def _server_salt() -> bytes:
    """Optional HMAC salt for vault-side matching. Public check uses plain SHA-256."""
    env = os.environ.get("LEAKTRACKER_SALT", "").encode()
    if env:
        return env
    # Deterministic local default so tests are stable. Rotate in production via env.
    return b"keyscout-leaktracker-dev-salt-v1"


def fingerprint_sha256(raw_key: str) -> str:
    """Public fingerprint (HIBP-style). High-entropy keys are not rainbow-tableable."""
    return hashlib.sha256(raw_key.encode("utf-8", errors="replace")).hexdigest()


def fingerprint_hmac(raw_key: str) -> str:
    """Internal fingerprint keyed with LEAKTRACKER_SALT (vault watch)."""
    return hmac.new(_server_salt(), raw_key.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()


def redact(raw_key: str, keep_prefix: int = 7, keep_suffix: int = 4) -> str:
    """Show a short prefix and suffix only. Never returns the full key."""
    if not raw_key:
        return ""
    if len(raw_key) <= keep_prefix + keep_suffix + 3:
        return raw_key[:2] + "…" + raw_key[-2:]
    return f"{raw_key[:keep_prefix]}…{raw_key[-keep_suffix:]}"


_SECRETISH = re.compile(
    r"(sk-[A-Za-z0-9_-]{10,}|sk_live_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{20,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})",
    re.IGNORECASE,
)


def scrub_text(text: str) -> str:
    """Remove secret-shaped substrings from log/error text before writing."""
    return _SECRETISH.sub("[REDACTED]", text)


def safe_match_record(raw_key: str, provider: str, rule_id: str) -> dict:
    """Build a disk-safe record from a raw match. Caller must drop raw_key after this."""
    return {
        "provider": provider,
        "rule_id": rule_id,
        "redacted": redact(raw_key),
        "fingerprint": fingerprint_sha256(raw_key),
        "fingerprint_hmac": fingerprint_hmac(raw_key),
    }
