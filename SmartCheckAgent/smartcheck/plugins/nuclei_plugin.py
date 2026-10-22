"""nuclei plugin: vuln_signature_scan.

Template-based signature scanning. IMPORTANT: nuclei results are *signatures*, not
proof. They become hypotheses / POSSIBLE findings for the reasoning engine to
validate — never auto-confirmed. The reasoning prompt enforces this discipline.
"""
from __future__ import annotations

import json
import shutil

from ..models import (CapabilityRequest, ExecutionType, Observation,
                      SafetyLevel, ValidationResult)
from .base import Plugin

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class NucleiPlugin(Plugin):
    name = "nuclei"
    capabilities = ["vuln_signature_scan"]
    execution_type = ExecutionType.ONE_SHOT
    # Default template run is active enumeration; keep it at ACTIVE and let the
    # engine avoid intrusive template tags.
    safety_level = SafetyLevel.ACTIVE
    binary = "nuclei"
    # Template loading + scanning takes far longer than one HTTP request.
    execution_timeout = 300

    def validate(self, request: CapabilityRequest) -> ValidationResult:
        if not shutil.which(self.binary):
            return ValidationResult(
                False,
                "nuclei not found. Install from ProjectDiscovery "
                "(e.g. `apt install nuclei` or the official release).",
            )
        if "://" not in request.target:
            return ValidationResult(
                False, "vuln_signature_scan target should be a full URL.")
        sev = request.params.get("severity")
        if sev:
            bad = set(str(sev).split(",")) - _VALID_SEVERITIES
            if bad:
                return ValidationResult(False, f"Invalid severities: {sorted(bad)}")
        argv = self.build_argv(request)
        return ValidationResult(True, argv=argv)

    def build_argv(self, request: CapabilityRequest) -> list[str]:
        p = request.params
        argv = [
            "nuclei", "-u", request.target,
            "-jsonl", "-silent", "-no-color",
            "-timeout", str(int(p.get("timeout", 10))),
            "-rate-limit", str(int(p.get("rate_limit", 50))),
            "-disable-update-check",
        ]
        # Default to excluding templates likely to be intrusive/noisy unless the
        # caller explicitly opts in.
        if not p.get("allow_intrusive"):
            argv += ["-exclude-tags", "dos,intrusive,fuzz,brute-force"]
        if p.get("severity"):
            argv += ["-severity", str(p["severity"])]
        if p.get("tags"):
            argv += ["-tags", str(p["tags"])]
        if p.get("templates"):
            argv += ["-t", str(p["templates"])]
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
            info = rec.get("info", {}) or {}
            classification = info.get("classification", {}) or {}
            cwe = classification.get("cwe-id") or []
            cve = classification.get("cve-id") or []
            observations.append(Observation(
                kind="vuln_signature",
                data={
                    "template_id": rec.get("template-id"),
                    "name": info.get("name", ""),
                    "severity": info.get("severity", "info"),
                    "matched_at": rec.get("matched-at") or rec.get("host", ""),
                    "type": rec.get("type", ""),
                    "cwe": cwe if isinstance(cwe, list) else [cwe],
                    "cve": cve if isinstance(cve, list) else [cve],
                    "tags": info.get("tags", []),
                    "description": info.get("description", ""),
                    "reference": info.get("reference", []),
                    # Explicit reminder carried into the data for the engine.
                    "note": "signature match — requires validation before confirming",
                },
                summary=f"[{info.get('severity', 'info')}] {rec.get('template-id')} "
                        f"@ {rec.get('matched-at', request.target)} (unvalidated)",
            ))
        if not observations:
            observations.append(Observation(
                kind="scan_complete",
                data={"target": request.target, "matches": 0},
                summary=f"nuclei found no template matches for {request.target}.",
            ))
        return observations
