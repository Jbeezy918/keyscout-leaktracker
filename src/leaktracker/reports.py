"""Provider report DRAFTS. Generated on disk, never sent."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .store import Store, utcnow

# Official-ish routes (human review before any send). We never auto-email.
PROVIDER_ROUTES = {
    "openai": {
        "channel": "OpenAI coordinated vulnerability disclosure / help.openai.com",
        "url": "https://openai.com/policies/coordinated-vulnerability-disclosure-policy/",
        "notes": "Prefer CVD/Bugcrowd. Do not paste full keys in public tickets. GitHub partner may already cover github_commit sources.",
    },
    "anthropic": {
        "channel": "Anthropic Responsible Disclosure",
        "url": "https://www.anthropic.com/responsible-disclosure-policy",
        "notes": "Anthropic auto-revokes keys found via GitHub partner program. Skip duplicate github reports when partner_likely=1.",
    },
    "stripe": {
        "channel": "Stripe support / security",
        "url": "https://support.stripe.com/",
        "notes": "Owner should roll key in Dashboard → Developers → API keys. Check current security email before sending.",
    },
    "aws": {
        "channel": "AWS security / support (exposed credentials)",
        "url": "https://aws.amazon.com/security/",
        "notes": "Owner should deactivate IAM access key. Do not use the key.",
    },
    "google": {
        "channel": "Google Cloud / Google security reporting",
        "url": "https://cloud.google.com/support/",
        "notes": "Owner deletes key in APIs & Services → Credentials.",
    },
    "github": {
        "channel": "GitHub support (for ghp_ tokens) — often auto-revoked",
        "url": "https://support.github.com/",
        "notes": "GitHub often auto-revokes exposed PATs.",
    },
    "slack": {
        "channel": "Slack security",
        "url": "https://slack.com/help/",
        "notes": "Rotate token in Slack app settings.",
    },
    "huggingface": {
        "channel": "Hugging Face security",
        "url": "https://huggingface.co/security",
        "notes": "Revoke token in HF settings.",
    },
}


def draft_path_for(drafts_dir: Path, finding_id: int) -> Path:
    return Path(drafts_dir) / f"report_{finding_id}.md"


def build_draft(row: dict[str, Any]) -> str:
    provider = row["provider"]
    route = PROVIDER_ROUTES.get(
        provider,
        {
            "channel": f"{provider} security contact (check)",
            "url": "(look up official security page)",
            "notes": "Verify the official reporting channel before any human send.",
        },
    )
    partner = "yes" if row.get("github_partner_likely") else "no"
    return f"""# Provider report DRAFT — DO NOT SEND AUTOMATICALLY

Generated: {utcnow()}
Finding id: {row.get('id')}
Status: DRAFT ONLY — KeyScout Leak Tracker never sends this.

## Target provider
- Provider: `{provider}`
- Channel: {route['channel']}
- URL: {route['url']}
- Notes: {route['notes']}
- Likely already covered by GitHub secret-scanning partner: **{partner}**

## What we found (redacted)
- Rule: `{row.get('rule_id')}`
- Redacted match: `{row.get('redacted')}`
- Fingerprint (sha256): `{row.get('fingerprint')}`
- Source type: `{row.get('source_type')}`
- Public locator: {row.get('public_locator')}
- Found at: {row.get('found_at')}

## What we did NOT do
- We did **not** validate or use this credential against any API.
- We did **not** revoke anything (only the issuer or owner can).
- We did **not** open a GitHub issue on the repository.

## Suggested message body (human edit before send)

Hello,

We operate a read-only public leak radar. A credential matching your
`{provider}` format appears at:

{row.get('public_locator')}

Redacted form: `{row.get('redacted')}`
SHA-256 fingerprint: `{row.get('fingerprint')}`

Please validate and revoke if appropriate, and notify the owner.
We have not used the credential.

Thank you
"""


def write_drafts(
    store: Store,
    drafts_dir: Path,
    *,
    limit: int = 50,
    skip_github_partner: bool = True,
) -> dict[str, int]:
    """Write draft markdown files for findings not yet marked reported."""
    drafts_dir = Path(drafts_dir)
    drafts_dir.mkdir(parents=True, exist_ok=True)
    rows = store.conn.execute(
        """SELECT * FROM findings WHERE status_reported=0
           ORDER BY id ASC LIMIT ?""",
        (limit,),
    ).fetchall()
    written = 0
    skipped_partner = 0
    for row in rows:
        d = dict(row)
        if skip_github_partner and d.get("github_partner_likely"):
            # Still write a draft but mark as deferred/skipped note
            skipped_partner += 1
            # Mark reported with a "skipped_partner" draft so we don't loop forever
            path = draft_path_for(drafts_dir, int(d["id"]))
            path.write_text(
                build_draft(d)
                + "\n\n## Auto-defer\nSkipped active send recommendation because GitHub partner likely already notified this provider for github_* sources.\n",
                encoding="utf-8",
            )
            store.mark_reported(int(d["id"]), str(path))
            written += 1
            continue
        path = draft_path_for(drafts_dir, int(d["id"]))
        path.write_text(build_draft(d), encoding="utf-8")
        store.mark_reported(int(d["id"]), str(path))
        written += 1
    return {"drafts_written": written, "skipped_partner_noted": skipped_partner}
