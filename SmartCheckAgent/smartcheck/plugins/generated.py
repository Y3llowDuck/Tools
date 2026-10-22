"""Declarative, data-driven plugins created by `plugin add`.

A GeneratedPlugin is built from a JSON *adapter spec* (no executable code), so
onboarding a tool never runs LLM-written Python and never touches the engine.
The spec describes how to build an argv (statically, from the spec + validated
params) and how to parse the tool's output into observations.

Spec shape (see validate_spec for the authoritative checks):

{
  "name": "ffuf",
  "binary": "ffuf",
  "capabilities": ["web_content_discovery"],
  "safety_level": "active",            # passive|active|intrusive|dangerous
  "execution_type": "one_shot",        # only one_shot supported here
  "execution_timeout": 240,            # optional
  "version_arg": "-V",                 # optional, for onboarding display
  "argv": {
    "base": ["ffuf", "-json", "-s"],
    "target": {"mode": "flag", "flag": "-u"},   # mode: flag|positional|none
    "params": [
      {"name": "wordlist", "flag": "-w", "required": true,
       "type": "path", "default_paths": ["/usr/share/wordlists/dirb/common.txt"]},
      {"name": "depth", "flag": "-recursion-depth", "type": "int", "default": 1},
      {"name": "match_codes", "flag": "-mc", "type": "str"}
    ]
  },
  "parser": {
    "type": "json_lines",              # json_lines|json|regex|lines|none
    "record_path": "results",          # for type=json (dotted path to a list)
    "observation_kind": "discovered_path",
    "filter": {"key": "type", "equals": "response"},   # optional
    "fields": {"url": "url", "status": "status", "length": "length"},
    "summary": "{status} {url} ({length})"
  }
}
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from ..models import (CapabilityRequest, ExecutionType, Observation,
                      SafetyLevel, ValidationResult)
from .base import Plugin

_SAFETY = {s.value for s in SafetyLevel}
_PARSER_TYPES = {"json_lines", "json", "regex", "lines", "none"}
_PARAM_TYPES = {"str", "int", "path", "flag", "list"}
# Reject obviously unsafe argv tokens even though we never use a shell.
_ARGV_TOKEN_OK = re.compile(r"^[^\x00]*$")


class SpecError(Exception):
    """Raised when an adapter spec is structurally invalid."""


def validate_spec(spec: dict) -> list[str]:
    """Return a list of error strings; empty means valid."""
    errs: list[str] = []
    if not isinstance(spec, dict):
        return ["spec must be an object"]

    for key in ("name", "binary", "capabilities", "safety_level", "argv", "parser"):
        if key not in spec:
            errs.append(f"missing required key: {key}")
    if errs:
        return errs

    if not re.match(r"^[a-z0-9_\-]+$", str(spec["name"])):
        errs.append("name must be lowercase alphanumeric/underscore/dash")
    if not isinstance(spec["capabilities"], list) or not spec["capabilities"]:
        errs.append("capabilities must be a non-empty list")
    if spec["safety_level"] not in _SAFETY:
        errs.append(f"safety_level must be one of {sorted(_SAFETY)}")
    if spec.get("execution_type", "one_shot") != "one_shot":
        errs.append("only execution_type 'one_shot' is supported")

    argv = spec["argv"]
    if not isinstance(argv, dict) or not isinstance(argv.get("base"), list) \
            or not argv["base"]:
        errs.append("argv.base must be a non-empty list")
    else:
        for tok in argv["base"]:
            if not isinstance(tok, str) or not _ARGV_TOKEN_OK.match(tok):
                errs.append(f"argv.base token invalid: {tok!r}")
    target = (argv or {}).get("target", {"mode": "none"})
    if target.get("mode") not in {"flag", "positional", "none"}:
        errs.append("argv.target.mode must be flag|positional|none")
    if target.get("mode") == "flag" and not target.get("flag"):
        errs.append("argv.target.mode 'flag' needs a flag")
    for p in (argv or {}).get("params", []) or []:
        if "name" not in p:
            errs.append("each param needs a name")
        if p.get("type", "str") not in _PARAM_TYPES:
            errs.append(f"param {p.get('name')!r} has bad type {p.get('type')}")

    parser = spec["parser"]
    if not isinstance(parser, dict) or parser.get("type") not in _PARSER_TYPES:
        errs.append(f"parser.type must be one of {sorted(_PARSER_TYPES)}")
    else:
        if parser["type"] in {"json_lines", "json"} and "observation_kind" not in parser:
            errs.append("json parser needs observation_kind")
        if parser["type"] == "regex" and "pattern" not in parser:
            errs.append("regex parser needs a pattern")
        if parser["type"] == "regex":
            try:
                re.compile(parser["pattern"])
            except re.error as e:
                errs.append(f"regex pattern invalid: {e}")
    return errs


def _dotted(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _host_only(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target


class GeneratedPlugin(Plugin):
    def __init__(self, spec: dict):
        errs = validate_spec(spec)
        if errs:
            raise SpecError("; ".join(errs))
        self.spec = spec
        self.name = spec["name"]
        self.binary = spec["binary"]
        self.capabilities = list(spec["capabilities"])
        self.safety_level = SafetyLevel(spec["safety_level"])
        self.execution_type = ExecutionType.ONE_SHOT
        self.execution_timeout = spec.get("execution_timeout")
        if spec.get("acceptable_return_codes"):
            self.acceptable_return_codes = set(spec["acceptable_return_codes"])

    # ---- argv ----------------------------------------------------------

    def build_argv(self, request: CapabilityRequest) -> list[str]:
        argv_spec = self.spec["argv"]
        argv: list[str] = list(argv_spec["base"])
        target_spec = argv_spec.get("target", {"mode": "none"})
        p = request.params or {}

        positional_target: Optional[str] = None
        target_value = request.target
        if target_spec.get("use_host_only"):
            target_value = _host_only(request.target)
        if target_spec.get("mode") == "flag":
            argv += [target_spec["flag"], target_value]
        elif target_spec.get("mode") == "positional":
            positional_target = target_value

        for param in argv_spec.get("params", []) or []:
            name = param["name"]
            ptype = param.get("type", "str")
            value = p.get(name, param.get("default"))
            if value is None and ptype == "path":
                value = _first_existing(param.get("default_paths", []))
            if value is None:
                continue  # required-ness is checked in validate()
            flag = param.get("flag")
            if ptype == "flag":
                if value and flag:
                    argv.append(flag)
                continue
            if ptype == "list" and isinstance(value, list):
                value = param.get("join", ",").join(str(v) for v in value)
            if flag:
                argv += [flag, str(value)]
            else:
                argv.append(str(value))

        if positional_target is not None:
            argv.append(positional_target)
        return argv

    # ---- validate ------------------------------------------------------

    def validate(self, request: CapabilityRequest) -> ValidationResult:
        if not shutil.which(self.binary):
            return ValidationResult(False, f"{self.binary} not found on PATH.")
        target_spec = self.spec["argv"].get("target", {"mode": "none"})
        if target_spec.get("requires_url") and "://" not in request.target:
            return ValidationResult(False, "this capability requires a full URL target.")
        p = request.params or {}
        for param in self.spec["argv"].get("params", []) or []:
            if param.get("required"):
                val = p.get(param["name"], param.get("default"))
                if val is None and param.get("type") == "path":
                    val = _first_existing(param.get("default_paths", []))
                if val is None:
                    return ValidationResult(
                        False, f"missing required param '{param['name']}'.")
        return ValidationResult(True, argv=self.build_argv(request))

    # ---- parse ---------------------------------------------------------

    def parse(self, raw_stdout: str, raw_stderr: str,
              request: CapabilityRequest) -> list[Observation]:
        parser = self.spec["parser"]
        ptype = parser["type"]
        if ptype == "none":
            return [Observation("tool_output",
                                {"target": request.target, "bytes": len(raw_stdout)},
                                summary=f"{self.name} completed.")]
        if ptype == "lines":
            obs = [Observation(parser.get("observation_kind", "line"),
                               {"line": ln}, summary=ln)
                   for ln in raw_stdout.splitlines() if ln.strip()]
            return obs or [self._empty(request)]
        if ptype == "regex":
            return self._parse_regex(raw_stdout, parser, request)
        if ptype == "json_lines":
            records = []
            for ln in raw_stdout.splitlines():
                ln = ln.strip()
                if ln.startswith("{"):
                    try:
                        records.append(json.loads(ln))
                    except json.JSONDecodeError:
                        pass
            return self._from_records(records, parser, request)
        if ptype == "json":
            try:
                doc = json.loads(raw_stdout)
            except json.JSONDecodeError:
                return [self._empty(request)]
            records = _dotted(doc, parser["record_path"]) if parser.get("record_path") \
                else doc
            if isinstance(records, dict):
                records = [records]
            return self._from_records(records or [], parser, request)
        return [self._empty(request)]

    def _from_records(self, records: list, parser: dict,
                      request: CapabilityRequest) -> list[Observation]:
        kind = parser.get("observation_kind", "record")
        fields = parser.get("fields", {})
        filt = parser.get("filter")
        summary_tpl = parser.get("summary")
        out: list[Observation] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if filt and str(rec.get(filt.get("key"))) != str(filt.get("equals")):
                continue
            data = {k: _dotted(rec, src) for k, src in fields.items()} if fields \
                else dict(rec)
            summary = ""
            if summary_tpl:
                try:
                    summary = summary_tpl.format(**{k: ("" if v is None else v)
                                                    for k, v in data.items()})
                except (KeyError, IndexError):
                    summary = str(data)
            out.append(Observation(kind, data, summary=summary))
        return out or [self._empty(request)]

    def _parse_regex(self, text: str, parser: dict,
                     request: CapabilityRequest) -> list[Observation]:
        kind = parser.get("observation_kind", "match")
        pat = re.compile(parser["pattern"])
        summary_tpl = parser.get("summary")
        out = []
        for m in pat.finditer(text):
            data = m.groupdict() or {"match": m.group(0)}
            summary = summary_tpl.format(**data) if summary_tpl else m.group(0)
            out.append(Observation(kind, data, summary=summary))
        return out or [self._empty(request)]

    def _empty(self, request: CapabilityRequest) -> Observation:
        return Observation("scan_complete",
                           {"target": request.target, "results": 0},
                           summary=f"{self.name} produced no parseable results.")

    # ---- persistence helpers ------------------------------------------

    @classmethod
    def from_file(cls, path: Path) -> "GeneratedPlugin":
        spec = json.loads(Path(path).read_text())
        return cls(spec)


def _first_existing(paths: list[str]) -> Optional[str]:
    for p in paths or []:
        if Path(p).exists():
            return p
    return None


def load_generated(directory: Path) -> list[GeneratedPlugin]:
    """Load every valid *.json adapter spec in a directory. Bad specs are skipped."""
    directory = Path(directory)
    plugins: list[GeneratedPlugin] = []
    if not directory.exists():
        return plugins
    for path in sorted(directory.glob("*.json")):
        try:
            plugins.append(GeneratedPlugin.from_file(path))
        except (SpecError, json.JSONDecodeError, OSError):
            continue
    return plugins
