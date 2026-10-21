# KeyScout Leak Tracker (Leak Radar)

Free, read-only radar for **public** GitHub events. Detects API-key *patterns*, stores **fingerprints + redactions only**, writes **provider report drafts (never auto-sent)**, re-checks public locators, and builds a **static dashboard** with weekly reports.

**Hard rules:** no key validation · no key use · no revocation · no full keys on disk · no auto-notifications.

## Demo

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./run.sh test
./run.sh all          # seed + short read-only poll + drafts + recheck + dashboard + weekly
./run.sh serve        # http://127.0.0.1:8765 — fingerprint check hashes in the browser only
```

Dashboard cards: **Found → Reported (drafts) → Removed → Confirmed**.  
Fingerprint check: Web Crypto SHA-256 in-page; compared to `fingerprints.json`.

## Features
- Prefix rules for OpenAI, Anthropic, Stripe, AWS, Google, GitHub, Slack, Hugging Face, SendGrid, Twilio, npm, PyPI, DigitalOcean, Supabase, Telegram (low false positives; benign fixture tested).
- GitHub Events watcher with **ETag**, **poll-interval**, and **exponential backoff** on 403/429; resume via SQLite meta.
- Weekly markdown/JSON report under `dashboard/reports/`.
- Provider report **drafts** only (`drafts/reports/`).

## Commands
| Command | Purpose |
|---|---|
| `./run.sh watch --once` | One poll |
| `./run.sh drafts` | Write provider drafts (not sent) |
| `./run.sh recheck` | Re-fetch locators |
| `./run.sh weekly` | Aggregate weekly report |
| `./run.sh dashboard` | Rebuild static site |

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License
Apache License 2.0 — see [LICENSE](LICENSE).
