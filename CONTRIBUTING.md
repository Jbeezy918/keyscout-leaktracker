# Contributing

## Hard rules (non-negotiable)
- **Never validate** found keys against provider APIs.
- **Never store** full keys on disk (fingerprints + redactions only).
- **Never auto-send** provider reports or open GitHub issues on strangers' repos.

## Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./run.sh test
ruff check src tests
```

## Good first issues
1. Add a low-FP rule for another provider (with benign fixture coverage).
2. npm / PyPI public package scanners (read-only).
3. Dashboard dark mode / accessibility pass.
4. Export Prometheus metrics for counters.
5. Document joining GitHub partner program (for *issuers*, not this scanner).

## Adding a rule
1. Add a `Rule` in `src/leaktracker/rules.py` with a **prefix** pattern.
2. Add a benign miss to `tests/fixtures/benign.txt`.
3. Add a positive case in tests.
4. Run `./run.sh test`.
