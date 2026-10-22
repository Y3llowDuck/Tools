"""curl plugin: http_request.

A single, controlled HTTP request. Defaults to a passive GET. Method, headers,
and body are accepted but constrained; the executor still enforces timeout and
rate limits. No following of redirects to arbitrary off-scope hosts: redirects
are reported, not auto-followed.
"""
from __future__ import annotations

import re
import shutil

from ..models import (CapabilityRequest, ExecutionType, Observation,
                      SafetyLevel, ValidationResult)
from .base import Plugin

_ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}
_HEADER_RE = re.compile(r"^[A-Za-z0-9\-]+:\s?.*$")


class CurlPlugin(Plugin):
    name = "curl"
    capabilities = ["http_request"]
    execution_type = ExecutionType.ONE_SHOT
    # A plain GET is passive; non-GET methods escalate (handled in validate()).
    safety_level = SafetyLevel.PASSIVE
    binary = "curl"

    def validate(self, request: CapabilityRequest) -> ValidationResult:
        if not shutil.which(self.binary):
            return ValidationResult(False, "curl binary not found on PATH.")
        if "://" not in request.target:
            return ValidationResult(
                False, "http_request target must be a full URL (http:// or https://)."
            )
        method = str(request.params.get("method", "GET")).upper()
        if method not in _ALLOWED_METHODS:
            return ValidationResult(False, f"Method {method!r} not allowed.")
        for h in request.params.get("headers", []) or []:
            if not _HEADER_RE.match(str(h)):
                return ValidationResult(False, f"Malformed header: {h!r}")
        argv = self.build_argv(request)
        return ValidationResult(True, argv=argv)

    def build_argv(self, request: CapabilityRequest) -> list[str]:
        p = request.params
        method = str(p.get("method", "GET")).upper()
        argv = [
            "curl", "-sS", "-i",          # silent-but-errors, include response headers
            "-o", "-",                     # body to stdout
            "--max-time", str(int(p.get("max_time", 30))),
            "-X", method,
        ]
        if not p.get("follow_redirects"):
            pass  # do NOT add -L by default; redirects are observed, not followed
        else:
            argv += ["-L", "--max-redirs", "3"]
        for h in p.get("headers", []) or []:
            argv += ["-H", str(h)]
        if "user_agent" in p:
            argv += ["-A", str(p["user_agent"])]
        body = p.get("data")
        if body is not None and method in {"POST", "PUT", "PATCH", "DELETE"}:
            argv += ["--data-binary", str(body)]
        if p.get("insecure"):
            argv += ["-k"]
        argv.append(request.target)
        return argv

    def parse(self, raw_stdout: str, raw_stderr: str,
              request: CapabilityRequest) -> list[Observation]:
        observations: list[Observation] = []
        # curl -i prints status line + headers, then blank line, then body.
        # With redirects there can be multiple header blocks; take the last.
        head, _, body = raw_stdout.rpartition("\r\n\r\n")
        if not head:
            head, _, body = raw_stdout.partition("\n\n")
        header_text = head if head else raw_stdout
        status_code = None
        headers: dict[str, str] = {}
        for line in header_text.splitlines():
            sm = re.match(r"HTTP/[\d.]+\s+(\d{3})", line)
            if sm:
                status_code = int(sm.group(1))
                headers = {}  # reset to keep the final response's headers
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        observations.append(Observation(
            kind="http_response",
            data={
                "url": request.target,
                "method": str(request.params.get("method", "GET")).upper(),
                "status_code": status_code,
                "server": headers.get("server", ""),
                "content_type": headers.get("content-type", ""),
                "content_length": _to_int(headers.get("content-length")),
                "location": headers.get("location", ""),
                "body_preview": body[:512],
                "headers": headers,
            },
            summary=f"{status_code} {request.target}"
                    + (f" -> {headers.get('location')}" if headers.get("location") else ""),
        ))
        return observations


def _to_int(v):
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None
