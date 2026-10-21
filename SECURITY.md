# Security Policy — KeyScout Leak Tracker

## What this tool does
- Scans **public** GitHub activity (and later other public sources) for known API-key *patterns*.
- Stores **redacted prefixes** and **SHA-256 fingerprints** only.
- Writes **provider report drafts** for a human to review.

## What this tool never does
- **Never validates** a found key against a provider API.
- **Never uses** a found key to call any service.
- **Never revokes** keys (only the issuing provider or the owner can).
- **Never stores** full keys on disk.
- **Never auto-sends** emails, webhooks to providers, or GitHub issues.

## Reporting a vulnerability in this project
Email the maintainers (see README) or open a private advisory once the GitHub repo exists.
Please include steps to reproduce. Do not include live production secrets in the report — redact them.

## If you find a leaked key with this tool
1. Roll/revoke it in the **provider dashboard**.
2. Optionally file a report using the provider's official security channel (see drafts under `drafts/reports/`).
3. Do not post the raw key in issues, tweets, or Discord.

## Fingerprint check
The public dashboard hashes keys in the browser (Web Crypto SHA-256) and compares against `fingerprints.json`.
Prefer pasting only into that local page, or hash offline and paste the hex digest.
