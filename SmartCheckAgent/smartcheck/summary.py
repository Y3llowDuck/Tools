"""Text summary of a run for the terminal.

Builds a consolidated, readable snapshot of what an assessment found, derived
from persisted observations/tests/findings. This is the terminal counterpart to
the (later) HTML report; it needs no API key.
"""
from __future__ import annotations

import json
from typing import Optional

from . import progress
from .db import Database


def _color(enabled: bool, text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _data(row) -> dict:
    try:
        return json.loads(row["data"] or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}


def _rule(title: str) -> str:
    return f"\n{'─' * 3} {title} " + "─" * max(0, 60 - len(title) - 5)


def build(db: Database, run_id: int, color: bool = False) -> str:
    run = db.get_run(run_id)
    if run is None:
        return f"No run #{run_id}."

    snap = progress.compute(db, run_id)
    out: list[str] = []
    bold = lambda t: _color(color, t, "1")  # noqa: E731

    # --- header --------------------------------------------------------
    out.append(bold(f"SmartCheckAgent — Assessment Summary"))
    out.append(f"Run #{run_id}  '{run['name']}'   status={run['status']}")
    out.append(f"Scope file: {run['scope_path']}")
    out.append(f"Started:    {run['created_at']}")

    # --- progress ------------------------------------------------------
    out.append(_rule("Progress"))
    out.append(progress.render(snap))

    # --- testing activity ----------------------------------------------
    counts = db.test_status_counts(run_id)
    out.append(_rule("Testing activity"))
    out.append(f"Total actions: {sum(counts.values())}   "
               f"ok={counts.get('ok', 0)}  "
               f"error={counts.get('error', 0)}  "
               f"blocked={counts.get('blocked', 0)}")

    # --- attack surface (derived from observations) --------------------
    out.append(_rule("Attack surface"))

    ports = db.observations(run_id, "open_port")
    if ports:
        out.append(bold("Open ports / services:"))
        for o in ports:
            d = _data(o)
            svc = d.get("service", "") or "?"
            ver = d.get("version", "")
            out.append(f"  {d.get('host')}:{d.get('port')}/{d.get('protocol')}"
                       f"  {svc}" + (f" {ver}" if ver else ""))
    else:
        out.append("Open ports / services: none observed.")

    https = db.observations(run_id, "http_response")
    if https:
        out.append(bold("\nHTTP responses:"))
        for o in https:
            d = _data(o)
            loc = f"  -> {d.get('location')}" if d.get("location") else ""
            out.append(f"  {d.get('status_code')}  {d.get('url')}"
                       f"  [{d.get('server', '')}{'; ' if d.get('server') else ''}"
                       f"{d.get('content_type', '')}]{loc}")

    probes = db.observations(run_id, "http_probe")
    if probes:
        out.append(bold("\nHTTP probes (httpx):"))
        for o in probes:
            d = _data(o)
            tech = ", ".join(d.get("tech") or [])
            out.append(f"  {d.get('status_code')}  {d.get('url')}"
                       f"  [{d.get('title', '')}]"
                       + (f"  tech: {tech}" if tech else ""))

    techs = db.observations(run_id, "technology")
    if techs:
        uniq = sorted({_data(o).get("technology", "") for o in techs} - {""})
        if uniq:
            out.append(bold("\nTechnologies detected: ") + ", ".join(uniq))

    paths = db.observations(run_id, "discovered_path")
    if paths:
        out.append(bold(f"\nDiscovered content ({len(paths)}):"))
        for o in paths:
            d = _data(o)
            out.append(f"  {d.get('status')}  {d.get('url')}"
                       f"  ({d.get('content_length')} bytes)")

    # --- leads needing validation (signatures / public exploits) -------
    sigs = db.observations(run_id, "vuln_signature")
    exploits = db.observations(run_id, "public_exploit")
    if sigs or exploits:
        out.append(_rule("Leads (require validation — NOT findings)"))
    if sigs:
        out.append(bold(f"Signature matches (nuclei, {len(sigs)}):"))
        for o in sigs:
            d = _data(o)
            cves = ", ".join(d.get("cve") or [])
            out.append(f"  [{d.get('severity')}] {d.get('template_id')} "
                       f"@ {d.get('matched_at')}"
                       + (f"  {cves}" if cves else ""))
    if exploits:
        out.append(bold(f"\nPublic exploits (searchsploit, {len(exploits)}):"))
        for o in exploits:
            d = _data(o)
            cves = ", ".join(d.get("cves") or [])
            out.append(f"  EDB-{d.get('edb_id')}: {d.get('title')}"
                       + (f"  [{cves}]" if cves else ""))

    # --- findings ------------------------------------------------------
    out.append(_rule("Findings"))
    findings = db.findings(run_id)
    if not findings:
        out.append("No findings recorded yet.")
        out.append("(Findings are produced once a hypothesis is validated: "
                   "Hypothesis → Test → Observation → Reproduce → Validate → Finding.)")
    else:
        for f in findings:
            tag = f"[{(f['status'] or '').upper()}]"
            sev = (f["severity"] or "info").upper()
            line = f"  {tag} {sev}  {f['title']}"
            if f["cwe"] or f["owasp"] or f["cvss_score"] is not None:
                extra = []
                if f["severity"] is not None and f["cvss_score"] is not None:
                    extra.append(f"CVSS {f['cvss_score']}")
                if f["cwe"]:
                    extra.append(f"CWE {f['cwe']}")
                if f["owasp"]:
                    extra.append(f"OWASP {f['owasp']}")
                line += "  (" + ", ".join(extra) + ")"
            out.append(line)

    # --- attack paths --------------------------------------------------
    paths_ = db.attack_paths(run_id)
    if paths_:
        out.append(_rule("Attack paths"))
        for ap in paths_:
            out.append(bold(f"  {ap['title']} ") + f"[{(ap['severity'] or '').upper()}]")
            try:
                steps = json.loads(ap["steps"] or "[]")
            except (json.JSONDecodeError, TypeError):
                steps = []
            for i, s in enumerate(steps, 1):
                if isinstance(s, dict):
                    ref = (f" (F-{s['finding_id']})" if s.get("finding_id") is not None
                           else "")
                    out.append(f"    {i}. {s.get('action', '')}{ref}")
                else:
                    out.append(f"    {i}. {s}")

    # --- scope-blocked actions (audit) ---------------------------------
    blocked = db.blocked_tests(run_id)
    if blocked:
        out.append(_rule("Blocked actions (audit trail)"))
        for b in blocked:
            out.append(f"  {b['capability']} -> {b['target']}: {b['reason']}")

    # --- evidence pointer ----------------------------------------------
    out.append(_rule("Evidence"))
    out.append("Raw tool output retained under: data/evidence/")

    return "\n".join(out)
