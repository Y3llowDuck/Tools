"""Standalone offline HTML pentest report generator.

Reads a run from SQLite and renders a single self-contained HTML file (inline CSS,
no external resources, print-friendly). It pulls ONLY structured data and tool
evidence — never the model's chain-of-thought, prompts, API keys, or tokens.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__, progress
from .db import Database
from .scope import Scope, ScopeError

# Severity ordering + palette (also used for the dashboard bars).
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#7b1fa2",
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#f9a825",
    "info": "#1565c0",
}
_MAX_EVIDENCE_CHARS = 20000  # cap embedded raw output per test

# Authorization fields must be entered by a human in scope.yaml — the agent never
# infers or fills them. These are the example-template placeholders (and the old
# silent defaults); any of them counts as "not provided" and blocks the report.
_AUTH_PLACEHOLDERS = {
    "",
    "your name / client contact",
    "describe the engagement / rules of engagement reference",
    "unspecified",
    "n/a",
    "tbd",
    "todo",
}


class UnauthorizedReportError(RuntimeError):
    """Raised when scope.yaml lacks real, human-entered authorization details."""


def _auth_missing(value: Optional[str]) -> bool:
    """True when an authorization field is blank or still a template placeholder."""
    return str(value or "").strip().lower() in _AUTH_PLACEHOLDERS


def _require_authorization(scope: Optional[Scope]) -> None:
    """Refuse to render a report unless a human filled authorization in scope.yaml.

    `authorized_by` and `engagement` must be present and must not be the
    example-template text. This is deliberately strict: a pentest report must
    never ship with fabricated, inferred, or placeholder sign-off — those fields
    are the user's to enter manually and the agent must not guess them.
    """
    if scope is None:
        raise UnauthorizedReportError(
            "scope.yaml could not be loaded, so authorization can't be verified. "
            "Create scope.yaml (copy scope.example.yaml) and fill the "
            "`authorization:` block before generating a report."
        )
    a = scope.authorization or {}
    missing = [k for k in ("authorized_by", "engagement") if _auth_missing(a.get(k))]
    if missing:
        raise UnauthorizedReportError(
            "Refusing to generate the report: the authorization field(s) "
            f"{', '.join(missing)} are blank or still placeholder text. "
            "Enter them MANUALLY in scope.yaml under `authorization:` "
            "(authorized_by, engagement). The agent never fills these for you."
        )


def _e(x) -> str:
    """HTML-escape any value."""
    return html.escape("" if x is None else str(x))


def _data(row) -> dict:
    try:
        return json.loads(row["data"] or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}


def _sev_rank(sev: str) -> int:
    try:
        return _SEV_ORDER.index((sev or "info").lower())
    except ValueError:
        return len(_SEV_ORDER)


def generate(db: Database, run_id: int, out_path: Path,
             scope: Optional[Scope] = None) -> Path:
    run = db.get_run(run_id)
    if run is None:
        raise ValueError(f"No run #{run_id}")

    snap = progress.compute(db, run_id)
    findings = db.findings(run_id)
    hypotheses = db.hypotheses(run_id)
    attack_paths = db.attack_paths(run_id)

    # Load scope for the methodology section (best-effort).
    if scope is None:
        try:
            scope = Scope.load(Path(run["scope_path"])) if run["scope_path"] else None
        except (ScopeError, Exception):
            scope = None

    # Authorization (authorized_by / engagement) must be human-entered in
    # scope.yaml; never inferred. Refuse rather than render placeholder text.
    _require_authorization(scope)

    sections = [
        _html_head(run),
        _cover(run, snap, findings),
        _exec_summary(run, snap, findings, db),
        _scope_methodology(run, scope, db),
        _attack_surface(db, run_id),
        _findings_summary(findings),
        _findings_detail(findings, hypotheses),
        _leads(db, run_id),
        _attack_paths_section(attack_paths),
        _statistics(db, run_id, snap),
        _evidence_appendix(db, run_id),
        _footer(),
        "</div></body></html>",
    ]
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(sections), encoding="utf-8")
    return out_path


# ---- sections ------------------------------------------------------------

def _html_head(run) -> str:
    title = f"SmartCheckAgent Report — {_e(run['name'])}"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{_CSS}</style>
</head><body><div class="wrap">"""


def _cover(run, snap, findings) -> str:
    counts = {s: 0 for s in _SEV_ORDER}
    confirmed = 0
    for f in findings:
        counts[(f["severity"] or "info").lower()] = counts.get(
            (f["severity"] or "info").lower(), 0) + 1
        if f["status"] == "confirmed":
            confirmed += 1
    dash = "".join(
        f'<div class="sevcard" style="border-color:{_SEV_COLOR[s]}">'
        f'<div class="sevnum" style="color:{_SEV_COLOR[s]}">{counts[s]}</div>'
        f'<div class="sevlbl">{s.title()}</div></div>'
        for s in _SEV_ORDER
    )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""
<header class="cover">
  <div class="brand">SmartCheckAgent</div>
  <h1>Security Assessment Report</h1>
  <div class="subtitle">{_e(run['name'])}</div>
  <table class="meta">
    <tr><th>Run ID</th><td>#{run['id']}</td></tr>
    <tr><th>Status</th><td>{_e(run['status'])}</td></tr>
    <tr><th>Started</th><td>{_e(run['created_at'])}</td></tr>
    <tr><th>Generated</th><td>{generated}</td></tr>
    <tr><th>Total findings</th><td>{len(findings)} ({confirmed} confirmed)</td></tr>
  </table>
  <div class="dash">{dash}</div>
  <p class="auth-warning">For authorized security testing only. This report may
  contain sensitive information; handle and distribute accordingly.</p>
</header>"""


def _exec_summary(run, snap, findings, db: Database) -> str:
    confirmed = [f for f in findings if f["status"] == "confirmed"]
    possible = [f for f in findings if f["status"] == "possible"]
    sev_counts = {}
    for f in confirmed:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    highest = min((f["severity"] for f in confirmed),
                  key=_sev_rank, default=None)

    bullets = []
    if confirmed:
        sev_desc = ", ".join(f"{n} {s}" for s, n in
                             sorted(sev_counts.items(), key=lambda kv: _sev_rank(kv[0])))
        bullets.append(f"<li><strong>{len(confirmed)} confirmed finding(s)</strong> "
                       f"({_e(sev_desc)}); highest severity "
                       f"<strong>{_e((highest or 'n/a').title())}</strong>.</li>")
    else:
        bullets.append("<li>No findings were confirmed during this assessment.</li>")
    if possible:
        bullets.append(f"<li>{len(possible)} additional finding(s) marked "
                       f"<em>possible</em>, pending further validation.</li>")
    bullets.append(f"<li>{snap.tests_count} test action(s) executed across the "
                   f"assessment; see Testing Statistics.</li>")

    top = ""
    if confirmed:
        rows = "".join(
            f"<li>{_sev_badge(f['severity'])} {_e(f['title'])}</li>"
            for f in sorted(confirmed, key=lambda f: _sev_rank(f["severity"]))[:5]
        )
        top = f"<p><strong>Key confirmed issues:</strong></p><ul class='plain'>{rows}</ul>"

    return f"""
<section id="exec"><h2>Executive Summary</h2>
<ul>{''.join(bullets)}</ul>
{top}
</section>"""


def _scope_methodology(run, scope: Optional[Scope], db: Database) -> str:
    if scope is not None:
        a = scope.authorization or {}
        auth = f"""<table class="kv">
        <tr><th>Authorized by</th><td>{_e(a.get('authorized_by', 'UNSPECIFIED'))}</td></tr>
        <tr><th>Engagement</th><td>{_e(a.get('engagement', 'n/a'))}</td></tr>
        <tr><th>Expires</th><td>{_e(a.get('expires', 'n/a'))}</td></tr></table>"""
        tgt = []
        if scope.ips:
            tgt.append("IPs: " + ", ".join(sorted(scope.ips)))
        if scope.networks:
            tgt.append("CIDRs: " + ", ".join(str(n) for n in scope.networks))
        if scope.domains:
            tgt.append("Domains: " + ", ".join(sorted(scope.domains)))
        if scope.url_hosts:
            tgt.append("URL hosts: " + ", ".join(sorted(scope.url_hosts)))
        ports = (", ".join(str(p) for p in sorted(scope.allowed_ports))
                 if scope.allowed_ports else "all (within in-scope hosts)")
        targets_html = "<ul class='plain'>" + "".join(
            f"<li>{_e(t)}</li>" for t in tgt) + f"<li>Ports: {_e(ports)}</li></ul>"
    else:
        auth = "<p class='muted'>Scope file not available at report time.</p>"
        targets_html = ""

    return f"""
<section id="scope"><h2>Scope &amp; Methodology</h2>
<h3>Authorization</h3>{auth}
<h3>Authorized targets</h3>{targets_html}
<h3>Methodology</h3>
<p>The assessment followed a PTES-aligned workflow — reconnaissance, enumeration,
vulnerability analysis, controlled testing, validation, and reporting — reasoning
from observed evidence rather than a fixed checklist. Weaknesses are classified
with reference to the OWASP Testing Guide and Top 10 (Web/API), mapped to CWE,
and rated with CVSS. Findings progress through
<em>Hypothesis → Test → Observation → Reproduce → Validate</em>; only reproduced
issues with concrete evidence are marked <strong>Confirmed</strong>. All actions
were constrained by deterministic scope validation, with no denial-of-service,
persistence, or destructive testing.</p>
</section>"""


def _attack_surface(db: Database, run_id: int) -> str:
    ports = db.observations(run_id, "open_port")
    probes = db.observations(run_id, "http_probe")
    paths = db.observations(run_id, "discovered_path")
    techs = db.observations(run_id, "technology")

    parts = ["<section id='surface'><h2>Attack Surface</h2>"]

    if ports:
        rows = "".join(
            f"<tr><td>{_e(_data(o).get('host'))}</td>"
            f"<td>{_e(_data(o).get('port'))}/{_e(_data(o).get('protocol'))}</td>"
            f"<td>{_e(_data(o).get('service'))}</td>"
            f"<td>{_e(_data(o).get('version'))}</td></tr>"
            for o in ports
        )
        parts.append("<h3>Open ports &amp; services</h3>"
                     "<table class='grid'><thead><tr><th>Host</th><th>Port</th>"
                     f"<th>Service</th><th>Version</th></tr></thead><tbody>{rows}</tbody></table>")

    if techs:
        uniq = sorted({_data(o).get("technology", "") for o in techs} - {""})
        if uniq:
            chips = "".join(f"<span class='chip'>{_e(t)}</span>" for t in uniq)
            parts.append(f"<h3>Technologies</h3><div>{chips}</div>")

    if probes:
        rows = "".join(
            f"<tr><td>{_e(_data(o).get('status_code'))}</td>"
            f"<td>{_e(_data(o).get('url'))}</td>"
            f"<td>{_e(_data(o).get('title'))}</td>"
            f"<td>{_e(', '.join(_data(o).get('tech') or []))}</td></tr>"
            for o in probes
        )
        parts.append("<h3>HTTP probes</h3>"
                     "<table class='grid'><thead><tr><th>Status</th><th>URL</th>"
                     f"<th>Title</th><th>Tech</th></tr></thead><tbody>{rows}</tbody></table>")

    if paths:
        rows = "".join(
            f"<tr><td>{_e(_data(o).get('status'))}</td>"
            f"<td>{_e(_data(o).get('url'))}</td>"
            f"<td>{_e(_data(o).get('content_length'))}</td></tr>"
            for o in paths
        )
        parts.append(f"<h3>Discovered content ({len(paths)})</h3>"
                     "<table class='grid'><thead><tr><th>Status</th><th>URL</th>"
                     f"<th>Bytes</th></tr></thead><tbody>{rows}</tbody></table>")

    if len(parts) == 1:
        parts.append("<p class='muted'>No attack-surface observations recorded.</p>")
    parts.append("</section>")
    return "".join(parts)


def _findings_summary(findings) -> str:
    if not findings:
        return ("<section id='fsum'><h2>Findings Summary</h2>"
                "<p class='muted'>No findings were recorded.</p></section>")
    rows = "".join(
        f"<tr><td class='nowrap'>F-{f['id']}</td><td>{_sev_badge(f['severity'])}</td>"
        f"<td>{_status_badge(f['status'])}</td>"
        f"<td><a href='#f{f['id']}'>{_e(f['title'])}</a></td>"
        f"<td class='nowrap'>{_e(f['cwe'])}</td><td class='nowrap'>{_e(f['owasp'])}</td>"
        f"<td class='nowrap'>{_e(f['cvss_score'])}</td></tr>"
        for f in findings
    )
    return f"""
<section id="fsum"><h2>Findings Summary</h2>
<table class="grid"><thead><tr><th class='nowrap'>ID</th><th>Severity</th><th>Status</th>
<th>Title</th><th class='nowrap'>CWE</th><th class='nowrap'>OWASP</th>
<th class='nowrap'>CVSS</th></tr></thead>
<tbody>{rows}</tbody></table></section>"""


def _findings_detail(findings, hypotheses) -> str:
    if not findings:
        return ""
    hyp_by_id = {h["id"]: h for h in hypotheses}
    cards = []
    for f in findings:
        maps = []
        if f["cwe"]:
            maps.append(f"<span class='chip'>CWE: {_e(f['cwe'])}</span>")
        if f["owasp"]:
            maps.append(f"<span class='chip'>OWASP: {_e(f['owasp'])}</span>")
        if f["cvss_score"] is not None:
            v = f" ({_e(f['cvss_vector'])})" if f["cvss_vector"] else ""
            maps.append(f"<span class='chip'>CVSS: {_e(f['cvss_score'])}{v}</span>")
        maps_html = "<div class='chips'>" + "".join(maps) + "</div>" if maps else ""

        hyp_html = ""
        if f["hypothesis_id"] and f["hypothesis_id"] in hyp_by_id:
            h = hyp_by_id[f["hypothesis_id"]]
            hyp_html = (f"<p class='muted'><strong>Originating hypothesis:</strong> "
                        f"{_e(h['statement'])}</p>")

        def block(label, text):
            return (f"<h4>{label}</h4><div class='prose'>{_para(text)}</div>"
                    if (text or "").strip() else "")

        cards.append(f"""
<div class="finding" id="f{f['id']}">
  <div class="fhead">
    <span class="fid">F-{f['id']}</span>
    {_sev_badge(f['severity'])} {_status_badge(f['status'])}
    <span class="ftitle">{_e(f['title'])}</span>
  </div>
  {maps_html}
  {block('Description', f['description'])}
  {block('Reproduction &amp; Evidence', f['reproduction'])}
  {block('Remediation', f['remediation'])}
  {hyp_html}
</div>""")
    return ("<section id='fdetail'><h2>Detailed Findings</h2>"
            + "".join(cards) + "</section>")


def _leads(db: Database, run_id: int) -> str:
    sigs = db.observations(run_id, "vuln_signature")
    exploits = db.observations(run_id, "public_exploit")
    if not (sigs or exploits):
        return ""
    parts = ["<section id='leads'><h2>Leads Requiring Validation</h2>",
             "<p class='muted'>The items below are automated signals (scanner "
             "signatures, public-exploit matches). They are <strong>not</strong> "
             "confirmed findings and must be validated before being relied upon.</p>"]
    if sigs:
        rows = "".join(
            f"<tr><td>{_sev_badge(_data(o).get('severity'))}</td>"
            f"<td>{_e(_data(o).get('template_id'))}</td>"
            f"<td>{_e(_data(o).get('matched_at'))}</td>"
            f"<td>{_e(', '.join(_data(o).get('cve') or []))}</td></tr>"
            for o in sigs
        )
        parts.append("<h3>Scanner signatures (nuclei)</h3>"
                     "<table class='grid'><thead><tr><th>Severity</th><th>Template</th>"
                     f"<th>Matched at</th><th>CVE</th></tr></thead><tbody>{rows}</tbody></table>")
    if exploits:
        rows = "".join(
            f"<tr><td>EDB-{_e(_data(o).get('edb_id'))}</td>"
            f"<td>{_e(_data(o).get('title'))}</td>"
            f"<td>{_e(', '.join(_data(o).get('cves') or []))}</td></tr>"
            for o in exploits
        )
        parts.append("<h3>Public exploits (searchsploit)</h3>"
                     "<table class='grid'><thead><tr><th>EDB-ID</th><th>Title</th>"
                     f"<th>CVE</th></tr></thead><tbody>{rows}</tbody></table>")
    parts.append("</section>")
    return "".join(parts)


def _attack_paths_section(attack_paths) -> str:
    if not attack_paths:
        return ""
    cards = []
    for ap in attack_paths:
        try:
            steps = json.loads(ap["steps"] or "[]")
        except (json.JSONDecodeError, TypeError):
            steps = []
        items = []
        for s in steps:
            if isinstance(s, dict):
                action = _e(s.get("action", ""))
                ref = ""
                if s.get("finding_id") is not None:
                    fid = _e(s["finding_id"])
                    ref += f" <a href='#f{fid}'>[F-{fid}]</a>"
                if (s.get("evidence") or "").strip():
                    ref += f" <span class='muted'>— {_e(s['evidence'])}</span>"
                items.append(f"<li>{action}{ref}</li>")
            else:
                items.append(f"<li>{_e(s)}</li>")
        mitre = (f"<div class='chips'><span class='chip'>MITRE: {_e(ap['mitre'])}"
                 f"</span></div>" if ap["mitre"] else "")
        cards.append(f"""<div class="finding">
          <div class="fhead"><span class="ftitle">{_e(ap['title'])}</span>
          {_sev_badge(ap['severity'])}</div>
          <div class='prose'>{_para(ap['description'])}</div>
          {mitre}
          <ol>{''.join(items)}</ol></div>""")
    return ("<section id='paths'><h2>Attack Paths</h2>" + "".join(cards) + "</section>")


def _statistics(db: Database, run_id: int, snap) -> str:
    status_counts = db.test_status_counts(run_id)
    kind_counts = db.observation_kind_counts(run_id)
    breakdown = db.capability_breakdown(run_id)

    sc_rows = "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>"
                      for k, v in sorted(status_counts.items()))
    kc_rows = "".join(f"<tr><td>{_e(r['kind'])}</td><td>{r['n']}</td></tr>"
                      for r in kind_counts)
    bd_rows = "".join(
        f"<tr><td>{_e(r['capability'])}</td><td>{_e(r['plugin'])}</td>"
        f"<td>{r['n']}</td><td>{r['total_seconds']:.1f}s</td></tr>"
        for r in breakdown
    )
    return f"""
<section id="stats"><h2>Testing Statistics</h2>
<div class="cols">
  <div><h3>Actions by status</h3><table class="grid"><thead><tr><th>Status</th>
  <th>Count</th></tr></thead><tbody>{sc_rows or '<tr><td colspan=2>-</td></tr>'}</tbody></table></div>
  <div><h3>Observations by kind</h3><table class="grid"><thead><tr><th>Kind</th>
  <th>Count</th></tr></thead><tbody>{kc_rows or '<tr><td colspan=2>-</td></tr>'}</tbody></table></div>
</div>
<h3>By capability</h3>
<table class="grid"><thead><tr><th>Capability</th><th>Plugin</th><th>Runs</th>
<th>Time</th></tr></thead><tbody>{bd_rows or '<tr><td colspan=4>-</td></tr>'}</tbody></table>
<p class="muted">Final progress: {snap.percent:.0f}% — phase {_e(snap.phase)}.</p>
</section>"""


def _evidence_appendix(db: Database, run_id: int) -> str:
    tests = db.tests_with_evidence(run_id)
    if not tests:
        return ""
    blocks = []
    for t in tests:
        raw = ""
        p = Path(t["evidence_path"])
        try:
            raw = p.read_text(errors="replace")[:_MAX_EVIDENCE_CHARS]
        except OSError:
            raw = "(evidence file unavailable)"
        blocks.append(f"""<details class="evidence">
          <summary>T-{t['id']} · {_e(t['capability'])} via {_e(t['plugin'])} ·
          {_e(t['target'])} · rc={_e(t['return_code'])}</summary>
          <pre>{_e(raw)}</pre></details>""")
    return (f"<section id='evidence'><h2>Evidence Appendix</h2>"
            f"<p class='muted'>Raw tool output retained for verification "
            f"({len(tests)} record(s)).</p>" + "".join(blocks) + "</section>")


def _footer() -> str:
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<footer class="foot">
    <p>Generated by SmartCheckAgent v{_e(__version__)} on {gen}.
    This report contains no model reasoning, prompts, or credentials.</p></footer>"""


# ---- small helpers -------------------------------------------------------

def _sev_badge(sev) -> str:
    s = (sev or "info").lower()
    color = _SEV_COLOR.get(s, "#555")
    return f"<span class='badge' style='background:{color}'>{_e(s.upper())}</span>"


def _status_badge(status) -> str:
    s = (status or "").lower()
    color = "#2e7d32" if s == "confirmed" else ("#ef6c00" if s == "possible" else "#777")
    return f"<span class='badge' style='background:{color}'>{_e(s.upper() or 'N/A')}</span>"


def _para(text) -> str:
    """Escape text and preserve paragraph/line breaks."""
    text = _e(text)
    paras = [p for p in text.split("\n\n")]
    return "".join(f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paras if p.strip())


_CSS = """
:root{--fg:#1a1a1a;--muted:#666;--line:#e0e0e0;--bg:#fff;--accent:#1565c0;}
*{box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  color:var(--fg);background:#f4f5f7;margin:0;line-height:1.55;}
.wrap{max-width:960px;margin:0 auto;background:var(--bg);padding:0 32px 48px;
  box-shadow:0 0 0 1px var(--line);}
h1{font-size:24px;margin:4px 0}h2{font-size:22px;border-bottom:2px solid var(--line);
  padding-bottom:6px;margin-top:40px}h3{font-size:16px;margin:20px 0 8px}
h4{font-size:14px;margin:14px 0 4px;color:var(--accent)}
a{color:var(--accent)}
.cover{padding:36px 0 20px;border-bottom:3px solid var(--accent)}
.brand{font-family:'Trebuchet MS',Futura,Verdana,sans-serif;font-weight:700;
  letter-spacing:1px;color:var(--accent);font-size:26px}
.subtitle{font-size:18px;color:var(--muted);margin-bottom:16px}
table.meta,table.kv{border-collapse:collapse;margin:12px 0}
table.meta th,table.kv th{text-align:left;padding:4px 16px 4px 0;color:var(--muted);
  font-weight:600;vertical-align:top;white-space:nowrap}
table.meta td,table.kv td{padding:4px 0}
.dash{display:flex;gap:10px;margin:20px 0;flex-wrap:wrap}
.sevcard{border:2px solid;border-radius:8px;padding:10px 16px;text-align:center;
  min-width:84px;flex:1}
.sevnum{font-size:28px;font-weight:700}.sevlbl{font-size:12px;color:var(--muted)}
.auth-warning{background:#fff8e1;border:1px solid #ffe082;padding:10px 14px;
  border-radius:6px;font-size:13px;color:#795548}
table.grid{border-collapse:collapse;width:100%;margin:10px 0;font-size:14px}
table.grid th,table.grid td{border:1px solid var(--line);padding:7px 10px;text-align:left;
  vertical-align:top;word-break:break-word}
table.grid thead th{background:#f0f2f5}
.badge{color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;
  letter-spacing:.5px;margin-right:6px;display:inline-block;white-space:nowrap}
.nowrap{white-space:nowrap}
.chip{display:inline-block;background:#eef1f5;border:1px solid var(--line);
  border-radius:12px;padding:2px 10px;font-size:12px;margin:2px 4px 2px 0}
.chips{margin:6px 0}
.finding{border:1px solid var(--line);border-left:4px solid var(--accent);
  border-radius:6px;padding:14px 18px;margin:16px 0;background:#fcfcfd}
.fhead{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.fid{font-weight:700;color:var(--muted);margin-right:6px}
.ftitle{font-weight:600;font-size:16px}
.prose p{margin:6px 0}
ul.plain{list-style:none;padding-left:0}ul.plain li{margin:4px 0}
.muted{color:var(--muted)}
.cols{display:flex;gap:24px;flex-wrap:wrap}.cols>div{flex:1;min-width:240px}
details.evidence{border:1px solid var(--line);border-radius:6px;margin:8px 0;
  background:#fafafa}
details.evidence summary{cursor:pointer;padding:8px 12px;font-size:13px;
  font-family:monospace;font-weight:600}
details.evidence pre{margin:0;padding:12px;background:#1e1e1e;color:#d4d4d4;
  overflow:auto;font-size:12px;border-radius:0 0 6px 6px;max-height:420px}
.foot{margin-top:48px;padding-top:16px;border-top:1px solid var(--line);
  font-size:12px;color:var(--muted)}
@media print{
  body{background:#fff}.wrap{box-shadow:none;max-width:100%}
  h2{page-break-after:avoid}.finding{page-break-inside:avoid}
  details.evidence[open] pre{max-height:none}
  details.evidence{page-break-inside:avoid}
  .foot{position:relative}
  a{color:var(--fg);text-decoration:none}
}
"""
