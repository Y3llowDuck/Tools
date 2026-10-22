"""feroxbuster plugin: web_content_discovery.

Runs feroxbuster in non-interactive mode emitting JSON lines, which we parse
into discovered-path observations. Wordlist and depth are constrained.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..models import (CapabilityRequest, ExecutionType, Observation,
                      SafetyLevel, ValidationResult)
from .base import Plugin

_DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]


def _default_wordlist() -> str | None:
    for w in _DEFAULT_WORDLISTS:
        if Path(w).exists():
            return w
    return None


class FeroxbusterPlugin(Plugin):
    name = "feroxbuster"
    capabilities = ["web_content_discovery"]
    execution_type = ExecutionType.ONE_SHOT
    safety_level = SafetyLevel.ACTIVE
    binary = "feroxbuster"
    # Directory brute-forcing runs longer than a single request timeout.
    execution_timeout = 240

    def validate(self, request: CapabilityRequest) -> ValidationResult:
        if not shutil.which(self.binary):
            return ValidationResult(False, "feroxbuster binary not found on PATH.")
        if "://" not in request.target:
            return ValidationResult(
                False, "web_content_discovery target must be a full URL."
            )
        wordlist = request.params.get("wordlist") or _default_wordlist()
        if not wordlist:
            return ValidationResult(
                False, "No wordlist found; pass params.wordlist=<path>."
            )
        if not Path(wordlist).exists():
            return ValidationResult(False, f"Wordlist not found: {wordlist}")
        depth = int(request.params.get("depth", 1))
        if not (1 <= depth <= 4):
            return ValidationResult(False, "depth must be between 1 and 4.")
        argv = self.build_argv(request)
        return ValidationResult(True, argv=argv)

    def build_argv(self, request: CapabilityRequest) -> list[str]:
        p = request.params
        wordlist = p.get("wordlist") or _default_wordlist()
        depth = int(p.get("depth", 1))
        threads = min(int(p.get("threads", 10)), 20)  # cap to stay polite
        rate = int(p.get("rate_limit", 0))            # requests/sec, 0 = unset
        argv = [
            "feroxbuster",
            "-u", request.target,
            "-w", str(wordlist),
            "-d", str(depth),
            "-t", str(threads),
            "--json",
            "--no-state",         # don't write a resume state file
            "--silent",           # emit only results (JSON lines) to stdout
            "-k",                 # allow self-signed certs on lab targets
        ]
        if rate > 0:
            argv += ["--rate-limit", str(rate)]
        statuses = p.get("status_codes")
        if statuses:
            argv += ["-s", ",".join(str(s) for s in statuses)]
        return argv

    def parse(self, raw_stdout: str, raw_stderr: str,
              request: CapabilityRequest) -> list[Observation]:
        observations: list[Observation] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") != "response":
                continue
            observations.append(Observation(
                kind="discovered_path",
                data={
                    "url": rec.get("url"),
                    "status": rec.get("status"),
                    "content_length": rec.get("content_length"),
                    "line_count": rec.get("line_count"),
                    "word_count": rec.get("word_count"),
                    "method": rec.get("method", "GET"),
                },
                summary=f"{rec.get('status')} {rec.get('url')} "
                        f"({rec.get('content_length')} bytes)",
            ))
        if not observations:
            observations.append(Observation(
                kind="scan_complete",
                data={"url": request.target, "found": 0},
                summary=f"No content discovered at {request.target}.",
            ))
        return observations
