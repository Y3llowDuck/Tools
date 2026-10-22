"""Promote parsed observations into the structured knowledge tables.

The capability pipeline already stores every :class:`Observation` verbatim (for
evidence and for the reasoning engine). This module additionally *normalizes*
the facts inside those observations into the first-class ``assets`` / ``services``
/ ``endpoints`` / ``parameters`` tables, so the attack surface is queryable and
progress accounting has real coverage numbers to work from (endpoints discovered
vs. endpoints tested) instead of always seeing zero.

Design rules:
  * Conservative — it never invents data a tool did not report.
  * Idempotent — upserts keep rows current; re-running a scan won't duplicate.
  * Non-fatal — the caller wraps this so a normalization slip can never break a
    scan (mirrors the "parsing must never crash the agent" rule in plugins).

Coverage semantics for progress:
  * discovery (feroxbuster paths, httpx probes) adds endpoints with ``tested=0``
    — they populate the *denominator*.
  * an actual request against a URL (curl ``http_request``, a nuclei match
    ``matched-at``) marks that endpoint ``tested=1`` — the *numerator*.
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qsl, urlparse, urlsplit

from .db import Database
from .models import CapabilityRequest, Observation

# Default TCP port implied by a URL scheme when the URL omits one.
_SCHEME_PORT = {"http": 80, "https": 443}


def _target_host(target: str) -> Optional[str]:
    """Best-effort host for a capability target (URL, host, or host:port)."""
    if "://" in target:
        return urlparse(target).hostname
    # bare host or host:port (lab targets are IPv4 / hostnames)
    if target.count(":") == 1:
        return target.split(":", 1)[0]
    return target or None


def _url_host_port_scheme(url: str) -> tuple[Optional[str], Optional[int], str]:
    pr = urlparse(url)
    if not pr.scheme:
        return None, None, ""
    try:
        port = pr.port
    except ValueError:
        port = None
    if port is None:
        port = _SCHEME_PORT.get(pr.scheme)
    return pr.hostname, port, pr.scheme


def _ensure_service_for_url(db: Database, run_id: int, url: str,
                            fallback_host: Optional[str]) -> Optional[int]:
    """Upsert the asset + service a URL implies; return the service id (or None)."""
    host, port, scheme = _url_host_port_scheme(url)
    host = host or fallback_host
    if not host:
        return None
    asset_id = db.add_asset(run_id, "host", host)
    if port is None:
        return None
    return db.add_service(run_id, asset_id, port, "tcp",
                          name=scheme or "http", state="open")


def _record_query_params(db: Database, run_id: int, endpoint_id: int, url: str) -> None:
    query = urlsplit(url).query
    if not query:
        return
    for name, value in parse_qsl(query, keep_blank_values=True):
        db.add_parameter(run_id, endpoint_id, name, location="query", example=value)


# ---- per-observation handlers -----------------------------------------------

def _h_open_port(db: Database, run_id: int, obs: Observation,
                 req: CapabilityRequest, target_host: Optional[str]) -> None:
    d = obs.data
    host = d.get("host") or target_host
    if not host:
        return
    asset_id = db.add_asset(run_id, "host", host)
    port = d.get("port")
    if port is None:
        return
    db.add_service(run_id, asset_id, int(port), d.get("protocol") or "tcp",
                   name=d.get("service") or "", version=d.get("version") or "",
                   state="open")


def _h_endpoint(tested: int):
    """Build a handler that records ``data['url']`` as an endpoint."""

    def handler(db: Database, run_id: int, obs: Observation,
                req: CapabilityRequest, target_host: Optional[str]) -> None:
        d = obs.data
        url = d.get("url")
        if not url or "://" not in url:
            return
        service_id = _ensure_service_for_url(db, run_id, url, target_host)
        endpoint_id = db.add_endpoint(
            run_id, url,
            method=str(d.get("method") or "GET").upper(),
            service_id=service_id,
            status_code=d.get("status_code") if d.get("status_code") is not None
            else d.get("status"),
            content_type=d.get("content_type") or "",
            content_length=d.get("content_length"),
            tested=tested,
        )
        _record_query_params(db, run_id, endpoint_id, url)

    return handler


def _h_vuln_signature(db: Database, run_id: int, obs: Observation,
                      req: CapabilityRequest, target_host: Optional[str]) -> None:
    # A signature match's "matched-at" is often a concrete URL that was probed.
    matched = obs.data.get("matched_at") or ""
    if "://" not in matched:
        return
    service_id = _ensure_service_for_url(db, run_id, matched, target_host)
    db.add_endpoint(run_id, matched, service_id=service_id, tested=1)


# kind -> handler. Kinds not listed (scan_complete, technology, http_response's
# structured-only fields, ...) are intentionally left as plain observations.
_HANDLERS = {
    "open_port": _h_open_port,
    "http_response": _h_endpoint(tested=1),   # curl actively requested this URL
    "discovered_path": _h_endpoint(tested=0),  # feroxbuster found it
    "http_probe": _h_endpoint(tested=0),       # httpx probed the base URL
    "vuln_signature": _h_vuln_signature,
}


def normalize(db: Database, run_id: Optional[int], request: CapabilityRequest,
              observations: list[Observation]) -> None:
    """Fold a capability's observations into the structured knowledge tables."""
    if run_id is None:
        return
    target_host = _target_host(request.target)
    # Always record the target host itself, so the attack surface shows it even
    # when a scan comes back empty.
    if target_host:
        db.add_asset(run_id, "host", target_host)
    for obs in observations:
        handler = _HANDLERS.get(obs.kind)
        if handler is None:
            continue
        handler(db, run_id, obs, request, target_host)
