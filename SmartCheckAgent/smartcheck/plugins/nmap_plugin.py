"""nmap plugin: network_discovery + service_detection.

Parses nmap's greppable (-oG -) output to avoid XML dependencies and keep the
normalized observations simple.
"""
from __future__ import annotations

import re
import shutil
from urllib.parse import urlparse

from ..models import (CapabilityRequest, ExecutionType, Observation,
                      SafetyLevel, ValidationResult)
from ..scope import parse_port_spec
from .base import Plugin

# Conservative default port set; a request may override with explicit `ports`.
_DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995," \
                 "1723,3306,3389,5432,5900,8000,8080,8443,8888"
_PORTSPEC_RE = re.compile(r"^[0-9,\-]+$")


def _host_only(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    # strip :port if present (but keep bare IPv6)
    if target.count(":") == 1:
        return target.split(":")[0]
    return target


class NmapPlugin(Plugin):
    name = "nmap"
    capabilities = ["network_discovery", "service_detection"]
    execution_type = ExecutionType.ONE_SHOT
    safety_level = SafetyLevel.ACTIVE
    binary = "nmap"

    def validate(self, request: CapabilityRequest) -> ValidationResult:
        if not shutil.which(self.binary):
            return ValidationResult(False, "nmap binary not found on PATH.")
        ports = request.params.get("ports")
        if ports is not None and not _PORTSPEC_RE.match(str(ports)):
            return ValidationResult(
                False, f"Invalid port spec {ports!r}; use digits, commas, and dashes."
            )
        argv = self.build_argv(request)
        return ValidationResult(True, argv=argv)

    def _effective_ports(self, request: CapabilityRequest) -> str:
        """Port spec to scan: explicit param, else the authorized set, else default."""
        if request.params.get("ports") is not None:
            return str(request.params["ports"])
        if request.scope_allowed_ports:
            return ",".join(str(p) for p in sorted(request.scope_allowed_ports))
        return _DEFAULT_PORTS

    def ports_for(self, request: CapabilityRequest):
        try:
            return parse_port_spec(self._effective_ports(request)) or None
        except ValueError:
            # Oversized range: let validate()/router reject it rather than crash.
            return None

    def build_argv(self, request: CapabilityRequest) -> list[str]:
        host = _host_only(request.target)
        ports = self._effective_ports(request)
        argv = ["nmap", "-Pn", "-T3"]
        if request.capability == "service_detection":
            argv += ["-sV"]
        # No -A (too intrusive), no NSE scripts by default; stays ACTIVE.
        argv += ["-p", ports, "-oG", "-", host]
        return argv

    def parse(self, raw_stdout: str, raw_stderr: str,
              request: CapabilityRequest) -> list[Observation]:
        observations: list[Observation] = []
        host = _host_only(request.target)
        for line in raw_stdout.splitlines():
            if "Ports:" not in line:
                continue
            # Host: 1.2.3.4 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
            m = re.search(r"Host:\s+(\S+).*Ports:\s+(.*?)(?:\tIgnored|$)", line)
            if not m:
                continue
            ip = m.group(1)
            for entry in m.group(2).split(","):
                parts = entry.strip().split("/")
                if len(parts) < 7:
                    continue
                port, state, proto, _, svc, _, ver = parts[:7]
                if state != "open":
                    continue
                observations.append(Observation(
                    kind="open_port",
                    data={"host": ip or host, "port": int(port), "protocol": proto,
                          "service": svc, "version": ver},
                    summary=f"{ip}:{port}/{proto} open"
                             + (f" ({svc}{' ' + ver if ver else ''})" if svc else ""),
                ))
        if not observations:
            observations.append(Observation(
                kind="scan_complete",
                data={"host": host, "open_ports": 0},
                summary=f"No open ports found on {host} for the scanned range.",
            ))
        return observations
