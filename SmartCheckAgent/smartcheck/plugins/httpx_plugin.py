"""httpx plugin (ProjectDiscovery): http_probe + tech_fingerprint.

NOTE ON THE BINARY: Kali ships the Python `httpx` HTTP-client CLI at
/usr/bin/httpx, which is NOT the ProjectDiscovery scanner. The pentest tool is
installed as `httpx-toolkit` on Kali. This plugin resolves the ProjectDiscovery
binary by name preference and a version-string check, so it never accidentally
drives the Python CLI.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

from ..models import (CapabilityRequest, ExecutionType, Observation,
                      SafetyLevel, ValidationResult)
from .base import Plugin

# Preference order: Kali's renamed binary first, then a plain `httpx` that we
# verify is actually ProjectDiscovery's.
_CANDIDATES = ["httpx-toolkit", "httpx-pd", "httpx"]


def _is_projectdiscovery(path: str) -> bool:
    try:
        r = subprocess.run([path, "-version"], capture_output=True, text=True,
                           timeout=5)
    except Exception:
        return False
    out = (r.stdout + r.stderr).lower()
    # PD httpx exits 0 on -version and mentions its name/version; the Python
    # httpx CLI errors on -version (unknown option), so rc != 0 excludes it.
    return r.returncode == 0 and ("projectdiscovery" in out or "httpx version" in out
                                  or "current version" in out)


class HttpxPlugin(Plugin):
    name = "httpx"
    capabilities = ["http_probe", "tech_fingerprint"]
    execution_type = ExecutionType.ONE_SHOT
    safety_level = SafetyLevel.ACTIVE
    binary = "httpx-toolkit"

    def resolve_binary(self) -> Optional[str]:
        for name in _CANDIDATES:
            path = shutil.which(name)
            if path and _is_projectdiscovery(path):
                return path
        return None

    def ports_for(self, request: CapabilityRequest):
        from ..scope import parse_port_spec
        ports = super().ports_for(request) or set()
        if request.params.get("ports"):
            try:
                ports |= parse_port_spec(str(request.params["ports"]))
            except ValueError:
                return None
        return ports or None

    def validate(self, request: CapabilityRequest) -> ValidationResult:
        path = self.resolve_binary()
        if not path:
            return ValidationResult(
                False,
                "ProjectDiscovery httpx not found. On Kali: `apt install httpx-toolkit` "
                "(the /usr/bin/httpx shipped by default is the unrelated Python CLI).",
            )
        argv = self.build_argv(request)
        return ValidationResult(True, argv=argv)

    def build_argv(self, request: CapabilityRequest) -> list[str]:
        path = self.resolve_binary() or "httpx-toolkit"
        p = request.params
        timeout = int(p.get("timeout", 10))
        argv = [
            path, "-u", request.target,
            "-json", "-silent", "-no-color",
            "-status-code", "-title", "-tech-detect",
            "-web-server", "-content-length", "-location", "-ip",
            "-timeout", str(timeout),
        ]
        if p.get("follow_redirects"):
            argv += ["-follow-redirects"]
        if p.get("ports"):
            argv += ["-ports", str(p["ports"])]
        if p.get("paths"):
            argv += ["-path", str(p["paths"])]
        return argv

    def parse(self, raw_stdout: str, raw_stderr: str,
              request: CapabilityRequest) -> list[Observation]:
        observations: list[Observation] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            tech = rec.get("tech") or rec.get("technologies") or []
            observations.append(Observation(
                kind="http_probe",
                data={
                    "url": rec.get("url"),
                    "input": rec.get("input"),
                    "status_code": rec.get("status_code") or rec.get("status-code"),
                    "title": rec.get("title", ""),
                    "webserver": rec.get("webserver", "") or rec.get("web_server", ""),
                    "tech": tech,
                    "content_length": rec.get("content_length"),
                    "ip": rec.get("host") or rec.get("ip", ""),
                    "location": rec.get("location", ""),
                    "scheme": rec.get("scheme", ""),
                    "port": rec.get("port", ""),
                },
                summary=f"{rec.get('status_code', '?')} {rec.get('url', '')}"
                        + (f" [{rec.get('title')}]" if rec.get("title") else "")
                        + (f" {','.join(tech)}" if tech else ""),
            ))
            # Surface each detected technology as its own observation for reasoning.
            for t in tech:
                observations.append(Observation(
                    kind="technology",
                    data={"url": rec.get("url"), "technology": t},
                    summary=f"tech: {t} @ {rec.get('url')}",
                ))
        if not observations:
            observations.append(Observation(
                kind="scan_complete",
                data={"target": request.target, "probed": 0},
                summary=f"httpx produced no probe result for {request.target}.",
            ))
        return observations
