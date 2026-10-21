"""Generate a static public dashboard (HTML + fingerprint index JSON)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .store import Store, utcnow


def _pivot(rows) -> dict[str, Any]:
    sources = sorted({r["source_type"] for r in rows}) or ["github_commit"]
    providers = sorted({r["provider"] for r in rows}) or ["openai"]
    grid = {s: {p: 0 for p in providers} for s in sources}
    for r in rows:
        grid[r["source_type"]][r["provider"]] = r["n"]
    return {"sources": sources, "providers": providers, "grid": grid}


def render_html(store: Store, *, test_label: str = "") -> str:
    counters = store.counters()
    pivot = _pivot(store.by_source_provider())
    recent = store.recent(20)
    label = test_label or "live / local data"
    # Build table
    hdr = "".join(f"<th>{p}</th>" for p in pivot["providers"]) + "<th>Total</th>"
    body_rows = []
    col_totals = {p: 0 for p in pivot["providers"]}
    for s in pivot["sources"]:
        cells = []
        row_total = 0
        for p in pivot["providers"]:
            n = pivot["grid"][s][p]
            col_totals[p] += n
            row_total += n
            cells.append(f"<td>{n}</td>")
        body_rows.append(f"<tr><td><code>{s}</code></td>{''.join(cells)}<td><strong>{row_total}</strong></td></tr>")
    foot = (
        "<tr><td><strong>Total</strong></td>"
        + "".join(f"<td><strong>{col_totals[p]}</strong></td>" for p in pivot["providers"])
        + f"<td><strong>{sum(col_totals.values())}</strong></td></tr>"
    )
    recent_html = "".join(
        "<tr>"
        f"<td>{r['found_at']}</td>"
        f"<td>{r['provider']}</td>"
        f"<td><code>{r['source_type']}</code></td>"
        f"<td><code>{r['redacted']}</code></td>"
        f"<td>{'Y' if r['status_reported'] else '—'}</td>"
        f"<td>{'Y' if r['status_removed'] else '—'}</td>"
        f"<td>{'Y' if r['status_confirmed'] else '—'}</td>"
        f"<td><a href=\"{r['public_locator']}\">locator</a></td>"
        "</tr>"
        for r in recent
    )
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KeyScout Leak Radar</title>
<style>
body{{font-family:-apple-system,Segoe UI,sans-serif;max-width:960px;margin:40px auto;padding:0 16px;color:#1f2933;line-height:1.5}}
h1{{color:#0b3d91}} .banner{{background:#fff3bf;border:1px solid #f59f00;padding:10px 14px;border-radius:8px}}
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}}
.card{{flex:1 1 140px;background:#f0f4f8;border-radius:10px;padding:14px}}
.card .n{{font-size:28px;font-weight:700;color:#0b3d91}}
table{{border-collapse:collapse;width:100%;font-size:14px;margin:12px 0}}
th,td{{border:1px solid #d9e2ec;padding:6px 8px;text-align:left}} th{{background:#f0f4f8}}
code{{background:#f0f4f8;padding:1px 4px}} input{{font-size:16px;padding:8px;width:min(480px,100%)}}
button{{font-size:16px;padding:8px 14px;margin-left:6px}}
#check-out{{margin-top:10px;padding:10px;background:#f8fafc;border-radius:8px;min-height:2em}}
.muted{{color:#627d98;font-size:13px}}
</style></head><body>
<h1>KeyScout Leak Radar</h1>
<p class="banner"><strong>Data label:</strong> {label}. Generated {utcnow()}.
We never validate or use found keys. We never revoke — providers do. Full keys are never stored.</p>

<div class="cards">
  <div class="card"><div class="n">{counters['found']}</div>Found</div>
  <div class="card"><div class="n">{counters['reported']}</div>Reported (drafts)</div>
  <div class="card"><div class="n">{counters['removed']}</div>Removed from source</div>
  <div class="card"><div class="n">{counters['confirmed']}</div>Provider confirmed</div>
</div>
<p class="muted">Also: last 24h found = {counters['found_24h']}; last 30d = {counters['found_30d']}.
"Reported" means a local provider-report <em>draft</em> was written — nothing is auto-sent.</p>

<h2>Counts by source × provider</h2>
<table>
<thead><tr><th>Source</th>{hdr}</tr></thead>
<tbody>
{''.join(body_rows) if body_rows else '<tr><td colspan="99">No findings yet.</td></tr>'}
{foot if body_rows else ''}
</tbody></table>

<h2>Check if my key leaked</h2>
<p>Hash locally in your browser (SHA-256 of the exact key string). We only compare fingerprints.
Paste a key below. Your browser computes <strong>SHA-256 locally</strong> (Web Crypto); only the hex digest is compared to the bundled <code>fingerprints.json</code>. The raw key never leaves this page (field is cleared after check).</p>
<p><input id="key" type="password" placeholder="paste key (hashed locally)" autocomplete="off">
<button id="go" type="button">Check</button>
<button id="clear" type="button">Clear</button></p>
<p class="muted">Or paste a SHA-256 hex fingerprint (64 chars) or a 10+ char prefix.</p>
<div id="check-out"></div>

<p class="muted"><a href="../reports/weekly_latest.md">Latest weekly report</a> (markdown).</p>

<h2>Recent findings (redacted)</h2>
<table>
<thead><tr><th>When</th><th>Provider</th><th>Source</th><th>Redacted</th><th>Draft</th><th>Gone</th><th>Confirmed</th><th>Link</th></tr></thead>
<tbody>{recent_html or '<tr><td colspan="8">None yet.</td></tr>'}</tbody>
</table>

<p class="muted">Part of <a href="https://getkeyscout.com">KeyScout</a> Leak Watch. Free radar · paid vault optional.
Apache-2.0. See SECURITY.md.</p>

<script>
async function sha256hex(str){{
  const enc=new TextEncoder().encode(str);
  const buf=await crypto.subtle.digest('SHA-256',enc);
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}}
let INDEX=null;
async function loadIndex(){{
  if(INDEX) return INDEX;
  const r=await fetch('fingerprints.json'); INDEX=await r.json(); return INDEX;
}}
document.getElementById('clear').onclick=()=>{{document.getElementById('key').value='';document.getElementById('check-out').textContent='';}};
document.getElementById('go').onclick=async()=>{{
  const out=document.getElementById('check-out');
  const v=document.getElementById('key').value.trim();
  if(!v){{out.textContent='Enter a key or fingerprint.';return;}}
  out.textContent='Checking…';
  try{{
    const idx=await loadIndex();
    let fp=v;
    if(!/^[0-9a-fA-F]{{10,64}}$/.test(v)) fp=await sha256hex(v);
    fp=fp.toLowerCase();
    const hits=(idx.fingerprints||[]).filter(x=>x===fp || (fp.length<64 && fp.length>=10 && x.startsWith(fp)));
    document.getElementById('key').value=''; // clear raw key from the field
    if(!hits.length) out.textContent='No match in this radar dataset for that fingerprint.';
    else out.innerHTML='<strong>'+hits.length+' match(es)</strong> for fingerprint <code>'+fp.slice(0,16)+'…</code>. Roll/revoke the key at the <em>provider</em> dashboard. We never revoke keys ourselves.';
  }}catch(e){{out.textContent='Could not load fingerprints.json ('+e+').';}}
}};
</script>
</body></html>
"""


def write_dashboard(store: Store, out_dir: Path, *, test_label: str = "") -> dict[str, str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "index.html"
    fp_path = out_dir / "fingerprints.json"
    stats_path = out_dir / "stats.json"
    html_path.write_text(render_html(store, test_label=test_label), encoding="utf-8")
    index = store.export_fingerprint_index()
    fp_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    stats = {
        "generated_at": utcnow(),
        "label": test_label,
        "counters": store.counters(),
        "by_source_provider": store.by_source_provider(),
    }
    stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    return {"html": str(html_path), "fingerprints": str(fp_path), "stats": str(stats_path)}
