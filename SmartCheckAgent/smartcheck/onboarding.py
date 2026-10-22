"""Automatic plugin onboarding for `plugin add <tool>`.

Flow: inspect the tool's help/version → ask the model to produce a DECLARATIVE
adapter spec (JSON, never code) → validate it structurally → optionally test it
against an in-scope target → show it and require approval → save + activate.

Adding a tool this way never changes the reasoning engine: the saved spec is
interpreted by GeneratedPlugin.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import config
from .executor import SafeExecutor
from .plugins.generated import GeneratedPlugin, validate_spec

# The schema description handed to the model. Kept terse and authoritative.
_SPEC_GUIDE = """\
Produce a single JSON object (no prose, no markdown fences) describing a
declarative adapter for the tool. Schema:

{
  "name": "<lowercase tool name>",
  "binary": "<exact binary on PATH>",
  "capabilities": ["<reuse an existing capability name when it fits, else a new "
                    "snake_case one>"],
  "safety_level": "passive|active|intrusive|dangerous",
  "execution_type": "one_shot",
  "execution_timeout": <seconds, optional; scanners need 120-300>,
  "version_arg": "<flag that prints version, optional>",
  "acceptable_return_codes": [0],
  "argv": {
    "base": ["<binary>", "<always-on flags, prefer machine-readable/JSON + quiet>"],
    "target": {"mode": "flag|positional|none", "flag": "<e.g. -u>",
               "requires_url": <true if target must be a URL>,
               "use_host_only": <true to strip scheme/port, e.g. for host args>},
    "params": [
      {"name": "<param>", "flag": "<cli flag or omit for positional>",
       "type": "str|int|path|flag|list", "required": <bool>,
       "default": <optional>, "default_paths": ["<for type=path>"],
       "join": "<list separator, default ','>"}
    ]
  },
  "parser": {
    "type": "json_lines|json|regex|lines|none",
    "record_path": "<for type=json: dotted path to the results list>",
    "observation_kind": "<snake_case, e.g. discovered_path, vuln_signature>",
    "filter": {"key": "<json key>", "equals": "<value>"},
    "fields": {"<obs field>": "<json key or dotted path>"},
    "pattern": "<for type=regex, with (?P<name>...) groups>",
    "summary": "<python format string using the obs fields>"
  }
}

Rules:
- Prefer a JSON/greppable output mode in argv.base so parsing is reliable.
- Choose safety_level conservatively: read-only probes = passive; normal
  enumeration/scanning = active; auth attempts/writes = intrusive; shells or
  state-changing exploitation = dangerous.
- Output ONLY the JSON object.
"""


@dataclass
class OnboardResult:
    spec: Optional[dict]
    errors: list[str] = field(default_factory=list)
    help_text: str = ""
    version_text: str = ""
    raw_model_output: str = ""


def gather_tool_info(binary: str, executor: SafeExecutor) -> tuple[str, str]:
    """Return (help_text, version_text) by probing the tool's own flags."""
    help_text = ""
    for flag in ("-h", "--help"):
        r = executor.run([binary, flag], timeout=10, save_evidence=False)
        text = (r.stdout or "") + (r.stderr or "")
        if text.strip():
            help_text = text
            break
    version_text = ""
    for flag in ("--version", "-V", "-version", "version"):
        r = executor.run([binary, flag], timeout=10, save_evidence=False)
        text = (r.stdout or "") + (r.stderr or "")
        if text.strip() and len(text) < 2000:
            version_text = text.strip()
            break
    return help_text[:8000], version_text[:500]


def _extract_json(text: str) -> Optional[dict]:
    """Pull the first JSON object out of a model response, tolerating fences."""
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.lower().startswith("json"):
            t = t[4:]
    start = t.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(t)):
        if t[i] == "{":
            depth += 1
        elif t[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(t[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def generate_spec(tool_name: str, help_text: str, version_text: str,
                  known_capabilities: list[str], model: str,
                  client_factory: Optional[Callable] = None) -> OnboardResult:
    """Ask the model to produce a declarative adapter spec from the tool's help."""
    from .reasoning.engine import _anthropic_client  # lazy; needs anthropic+creds
    client = (client_factory or _anthropic_client)()

    system = ("You convert a Kali tool's help text into a declarative adapter "
              "spec for SmartCheckAgent. " + _SPEC_GUIDE
              + "\n\nExisting capability names to reuse when appropriate: "
              + ", ".join(sorted(known_capabilities)) + ".")
    user = (f"Tool: {tool_name}\n\nVERSION:\n{version_text or '(unknown)'}\n\n"
            f"HELP:\n{help_text or '(no help captured)'}")

    try:
        resp = client.messages.create(
            model=model, max_tokens=2000,
            system=system, messages=[{"role": "user", "content": user}],
        )
    except Exception as e:  # noqa: BLE001
        return OnboardResult(None, [f"model call failed: {e}"])

    raw = "".join(getattr(b, "text", "") for b in resp.content
                  if getattr(b, "type", "") == "text")
    spec = _extract_json(raw)
    if spec is None:
        return OnboardResult(None, ["model did not return valid JSON"],
                             help_text, version_text, raw)
    # Force the name to the requested tool for consistency.
    spec.setdefault("name", tool_name)
    errs = validate_spec(spec)
    return OnboardResult(spec, errs, help_text, version_text, raw)


def save_spec(spec: dict, db=None) -> Path:
    """Write the spec to the generated-plugins dir and (optionally) record it."""
    config.ensure_dirs()
    path = config.GENERATED_PLUGINS_DIR / f"{spec['name']}.json"
    path.write_text(json.dumps(spec, indent=2))
    if db is not None:
        db.upsert_plugin(
            name=spec["name"], capabilities=spec["capabilities"],
            execution_type="one_shot", safety_level=spec["safety_level"],
            binary_path=shutil.which(spec["binary"]) or "", source="generated",
            status="active", metadata={"spec_path": str(path)},
        )
    return path


def build_plugin(spec: dict) -> GeneratedPlugin:
    """Instantiate (and thereby validate) a plugin from a spec."""
    return GeneratedPlugin(spec)
