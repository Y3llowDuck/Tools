"""searchsploit plugin: exploit_mapping.

Offline lookup against the local Exploit-DB. It sends NO traffic to the target,
so it is PASSIVE. To keep the scope contract meaningful, `target` still names the
in-scope asset the lookup pertains to (and is scope-validated as usual), while the
product/version to search for is passed in params['query'].

Example request:
    capability=exploit_mapping, target=192.168.56.10,
    params={"query": "vsftpd 2.3.4"}
"""
from __future__ import annotations

import json
import re
import shutil

from ..models import (CapabilityRequest, ExecutionType, Observation,
                      SafetyLevel, ValidationResult)
from .base import Plugin

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# Reject shell metacharacters defensively even though we never use a shell.
_QUERY_OK = re.compile(r"^[A-Za-z0-9 ._\-/+:]+$")


class SearchsploitPlugin(Plugin):
    name = "searchsploit"
    capabilities = ["exploit_mapping"]
    execution_type = ExecutionType.ONE_SHOT
    safety_level = SafetyLevel.PASSIVE  # offline; no target interaction
    binary = "searchsploit"

    def validate(self, request: CapabilityRequest) -> ValidationResult:
        if not shutil.which(self.binary):
            return ValidationResult(
                False, "searchsploit not found (install the `exploitdb` package).")
        query = str(request.params.get("query", "")).strip()
        if not query:
            return ValidationResult(
                False,
                "exploit_mapping needs params.query (e.g. a product + version like "
                "'vsftpd 2.3.4') observed on the in-scope target.",
            )
        if not _QUERY_OK.match(query):
            return ValidationResult(
                False, "query contains unsupported characters; use product/version text.")
        argv = self.build_argv(request)
        return ValidationResult(True, argv=argv)

    def build_argv(self, request: CapabilityRequest) -> list[str]:
        p = request.params
        query = str(p.get("query", "")).strip()
        argv = ["searchsploit", "--json"]
        if p.get("title_only"):
            argv.append("-t")
        if p.get("exclude"):
            argv.append(f"--exclude={p['exclude']}")
        argv += query.split()
        return argv

    def parse(self, raw_stdout: str, raw_stderr: str,
              request: CapabilityRequest) -> list[Observation]:
        observations: list[Observation] = []
        try:
            doc = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return [Observation(
                kind="scan_complete",
                data={"query": request.params.get("query"), "results": 0},
                summary="searchsploit returned no parseable results.",
            )]
        results = doc.get("RESULTS_EXPLOIT") or []
        for r in results:
            codes = r.get("Codes", "") or ""
            cves = _CVE_RE.findall(codes)
            observations.append(Observation(
                kind="public_exploit",
                data={
                    "title": r.get("Title"),
                    "edb_id": r.get("EDB-ID"),
                    "cves": cves,
                    "type": r.get("Type"),
                    "platform": r.get("Platform"),
                    "date": r.get("Date_Published"),
                    "path": r.get("Path"),
                    "query": doc.get("SEARCH"),
                    "for_asset": request.target,
                },
                summary=f"EDB-{r.get('EDB-ID')}: {r.get('Title')}"
                        + (f" [{', '.join(cves)}]" if cves else ""),
            ))
        if not observations:
            observations.append(Observation(
                kind="scan_complete",
                data={"query": doc.get("SEARCH"), "results": 0},
                summary=f"No public exploits found for '{doc.get('SEARCH')}'.",
            ))
        return observations
