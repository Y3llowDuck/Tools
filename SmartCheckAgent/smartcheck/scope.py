"""Deterministic scope enforcement.

This module is the single authority on whether a target is authorized. It does
NOT use any LLM and has no side effects beyond reading scope.yaml. Every
capability request must pass `Scope.check()` before the executor is reachable.

Design: deny-by-default. If scope.yaml is missing, malformed, or a target does
not explicitly match an allowed rule, the answer is "no".
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml

from . import config


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None
    # Parsed view of what was checked, useful for logging.
    host: Optional[str] = None
    port: Optional[int] = None


@dataclass
class Limits:
    requests_per_second: float = config.DEFAULT_REQUESTS_PER_SECOND
    request_timeout_seconds: int = config.DEFAULT_REQUEST_TIMEOUT_SECONDS
    max_concurrency: int = config.DEFAULT_MAX_CONCURRENCY


class ScopeError(Exception):
    """Raised when scope.yaml cannot be loaded or is structurally invalid."""


# Default scheme ports so a bare URL resolves to a port for port checks.
_SCHEME_PORTS = {"http": 80, "https": 443, "ftp": 21, "ssh": 22}


@dataclass
class Scope:
    ips: set[str] = field(default_factory=set)
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    domains: set[str] = field(default_factory=set)
    url_hosts: set[str] = field(default_factory=set)  # hosts seen in `urls:`
    allowed_ports: set[int] = field(default_factory=set)  # empty => all ports
    allow_subdomains: bool = False
    limits: Limits = field(default_factory=Limits)
    authorization: dict = field(default_factory=dict)
    source_path: Optional[Path] = None

    # ---- loading -------------------------------------------------------

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Scope":
        path = Path(path) if path else config.SCOPE_PATH
        if not path.exists():
            raise ScopeError(
                f"Scope file not found: {path}\n"
                f"Copy scope.example.yaml to scope.yaml and define authorized targets."
            )
        try:
            raw = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as e:
            raise ScopeError(f"Could not parse {path}: {e}") from e
        if not isinstance(raw, dict):
            raise ScopeError(f"{path} must be a YAML mapping.")

        targets = raw.get("targets") or {}
        scope = cls(source_path=path)

        for ip in targets.get("ips") or []:
            try:
                scope.ips.add(str(ipaddress.ip_address(str(ip))))
            except ValueError as e:
                raise ScopeError(f"Invalid IP in scope: {ip!r} ({e})") from e

        for cidr in targets.get("cidrs") or []:
            try:
                scope.networks.append(ipaddress.ip_network(str(cidr), strict=False))
            except ValueError as e:
                raise ScopeError(f"Invalid CIDR in scope: {cidr!r} ({e})") from e

        for d in targets.get("domains") or []:
            scope.domains.add(_norm_host(str(d)))

        for u in targets.get("urls") or []:
            parsed = urlparse(str(u))
            if parsed.hostname:
                host = _norm_host(parsed.hostname)
                # If the URL host is an IP literal, authorize it via the IP set so
                # the IP check path matches it; otherwise treat it as a hostname.
                ip_obj = _as_ip(host)
                if ip_obj is not None:
                    scope.ips.add(str(ip_obj))
                else:
                    scope.url_hosts.add(host)
                # A URL with an explicit port implicitly authorizes that port.
                if parsed.port:
                    scope.allowed_ports.add(int(parsed.port))

        ports = raw.get("ports") or {}
        for p in ports.get("allowed") or []:
            scope.allowed_ports.add(int(p))

        opts = raw.get("options") or {}
        scope.allow_subdomains = bool(opts.get("allow_subdomains", False))

        lim = raw.get("limits") or {}
        scope.limits = Limits(
            requests_per_second=float(lim.get("requests_per_second",
                                              config.DEFAULT_REQUESTS_PER_SECOND)),
            request_timeout_seconds=int(lim.get("request_timeout_seconds",
                                                config.DEFAULT_REQUEST_TIMEOUT_SECONDS)),
            max_concurrency=int(lim.get("max_concurrency",
                                        config.DEFAULT_MAX_CONCURRENCY)),
        )
        scope.authorization = raw.get("authorization") or {}

        if not (scope.ips or scope.networks or scope.domains or scope.url_hosts):
            raise ScopeError(
                f"{path} defines no targets. Add at least one ip, cidr, domain, or url."
            )
        return scope

    # ---- default target ------------------------------------------------

    #: Convenience entries that are usually in scope by default and are rarely
    #: the actual assessment target, so they don't count toward auto-selection.
    _LOOPBACK = {"localhost", "127.0.0.1", "::1"}

    def default_target(self) -> tuple[Optional[str], str]:
        """Return (target, reason) for a run when no target was given.

        Resolves to a single concrete host only when the scope is unambiguous:
        no CIDR ranges and exactly one non-loopback IP/host. Otherwise returns
        (None, explanation) so the caller can ask for an explicit target.
        """
        if self.networks:
            return None, ("scope includes CIDR range(s) "
                          f"{[str(n) for n in self.networks]}; "
                          "specify which host to start on.")
        candidates: list[str] = []
        for h in list(sorted(self.ips)) + list(sorted(self.url_hosts)) \
                + list(sorted(self.domains)):
            if h not in self._LOOPBACK and h not in candidates:
                candidates.append(h)
        if len(candidates) == 1:
            return candidates[0], f"the only concrete in-scope host is {candidates[0]}"
        if not candidates:
            return None, "no single concrete host in scope; specify a target."
        return None, (f"scope has multiple hosts {candidates}; specify which to start on.")

    # ---- checking ------------------------------------------------------

    def check(self, target: str, port: Optional[int] = None) -> ScopeDecision:
        """Return a ScopeDecision for a target (IP, hostname, or URL).

        A URL's scheme/explicit port is used for the port check when `port`
        is not given. Deny-by-default throughout.
        """
        if not target or not str(target).strip():
            return ScopeDecision(False, "Empty target.")

        host, parsed_port = _split_target(target)
        if host is None:
            return ScopeDecision(False, f"Could not parse a host from {target!r}.")
        effective_port = port if port is not None else parsed_port

        host_decision = self._check_host(host)
        host_decision.host = host
        host_decision.port = effective_port
        if not host_decision.allowed:
            return host_decision

        # Port check only applies when a port is actually involved.
        if effective_port is not None and self.allowed_ports:
            if effective_port not in self.allowed_ports:
                return ScopeDecision(
                    False,
                    f"Port {effective_port} is not in the allowed ports "
                    f"{sorted(self.allowed_ports)}.",
                    host=host, port=effective_port,
                )
        return host_decision

    def check_ports(self, ports) -> tuple[bool, list[int]]:
        """Validate a set/list of ports against allowed_ports.

        Returns (ok, out_of_scope_ports). If allowed_ports is empty (all ports
        permitted on in-scope hosts), everything passes.
        """
        if not self.allowed_ports:
            return True, []
        bad = sorted({int(p) for p in ports if int(p) not in self.allowed_ports})
        return (not bad), bad

    def _check_host(self, host: str) -> ScopeDecision:
        host = _norm_host(host)

        # Is it an IP literal?
        ip_obj = _as_ip(host)
        if ip_obj is not None:
            if str(ip_obj) in self.ips:
                return ScopeDecision(True, "IP explicitly in scope.",
                                     matched_rule=f"ip:{ip_obj}")
            for net in self.networks:
                if ip_obj.version == net.version and ip_obj in net:
                    return ScopeDecision(True, f"IP within authorized CIDR {net}.",
                                         matched_rule=f"cidr:{net}")
            return ScopeDecision(False, f"IP {host} is not in any authorized range.")

        # Hostname path.
        if host in self.domains or host in self.url_hosts:
            return ScopeDecision(True, "Hostname explicitly in scope.",
                                 matched_rule=f"host:{host}")
        if self.allow_subdomains:
            for d in self.domains:
                if host.endswith("." + d):
                    return ScopeDecision(True, f"Subdomain of authorized {d}.",
                                         matched_rule=f"subdomain:{d}")
        return ScopeDecision(False, f"Host {host!r} is not in scope.")


# ---- helpers -----------------------------------------------------------

def parse_port_spec(spec: str, cap: int = 65535) -> set[int]:
    """Expand a port spec like '22,80,8000-8010' into a set of ints.

    Ranges are expanded; invalid tokens are skipped. Raises ValueError if the
    spec would expand beyond `cap` ports (guards against absurd ranges).
    """
    ports: set[int] = set()
    for token in str(spec).split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            lo_s, _, hi_s = token.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            if hi - lo + 1 > cap:
                raise ValueError(f"port range {token} too large")
            ports.update(p for p in range(lo, hi + 1) if 1 <= p <= 65535)
        else:
            try:
                p = int(token)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    return ports


def _norm_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _split_target(target: str) -> tuple[Optional[str], Optional[int]]:
    """Return (host, port) from an IP, host, host:port, or URL. port may be None."""
    target = target.strip()
    # URL form?
    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname:
            return None, None
        port = parsed.port or _SCHEME_PORTS.get(parsed.scheme)
        return parsed.hostname, port

    # Bracketed IPv6 with optional port: [::1]:8080
    if target.startswith("["):
        end = target.find("]")
        if end != -1:
            host = target[1:end]
            rest = target[end + 1:]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    return host, None
            return host, None

    # Bare IPv6 literal (multiple colons, not host:port).
    if target.count(":") >= 2 and _as_ip(target) is not None:
        return target, None

    # host:port
    if target.count(":") == 1:
        host, _, p = target.partition(":")
        try:
            return host, int(p)
        except ValueError:
            return host, None

    return target, None
