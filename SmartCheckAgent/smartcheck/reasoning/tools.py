"""Tools exposed to the model, and the dispatcher that executes them.

The model can ONLY call these tools — there is no shell tool and no free-form
command. `request_capability` routes through the CapabilityRouter, which applies
the deterministic scope gate and safety ceiling before any execution.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..capabilities import CapabilityRouter
from ..db import Database
from ..models import CapabilityRequest
from ..progress import PHASE_ORDER


def tool_definitions(capabilities: list[str]) -> list[dict]:
    """JSON-schema tool definitions. `capabilities` constrains the enum."""
    return [
        {
            "name": "request_capability",
            "description": (
                "Request a testing capability against an authorized target. Python "
                "validates scope, selects a Kali tool, executes it safely, and "
                "returns normalized observations. This is the only way to interact "
                "with a target. You never run commands directly."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "enum": capabilities,
                        "description": "The capability to request.",
                    },
                    "target": {
                        "type": "string",
                        "description": "IP, hostname, or full URL. Must be in scope.",
                    },
                    "params": {
                        "type": "object",
                        "description": (
                            "Capability-specific parameters, e.g. "
                            "{\"ports\": \"22,80,443\"} for nmap, "
                            "{\"method\": \"POST\", \"data\": \"x=1\"} for curl, "
                            "{\"depth\": 2} for feroxbuster."
                        ),
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why you are requesting this (recorded for audit).",
                    },
                },
                "required": ["capability", "target", "reason"],
            },
        },
        {
            "name": "record_hypothesis",
            "description": (
                "Record a hypothesis about a potential weakness BEFORE testing it. "
                "Part of the validation discipline."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "statement": {"type": "string",
                                  "description": "The hypothesis, concisely."},
                    "rationale": {"type": "string",
                                  "description": "Evidence/reasoning that motivates it."},
                    "cwe": {"type": "string", "description": "e.g. CWE-89"},
                    "owasp": {"type": "string",
                              "description": "e.g. A01:2021 or API5:2023"},
                    "confidence": {"type": "number",
                                   "description": "0.0-1.0 prior confidence."},
                },
                "required": ["statement"],
            },
        },
        {
            "name": "record_finding",
            "description": (
                "Record a finding. Use status 'possible' when suggestive but "
                "unproven, 'confirmed' only when reproduced with concrete observed "
                "evidence (never from a scanner signature or banner alone). The "
                "reproduction field of a confirmed finding must cite observed evidence."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "status": {"type": "string", "enum": ["possible", "confirmed"]},
                    "severity": {"type": "string",
                                 "enum": ["info", "low", "medium", "high", "critical"]},
                    "cvss_score": {"type": "number"},
                    "cvss_vector": {"type": "string",
                                    "description": "e.g. CVSS:3.1/AV:N/AC:L/..."},
                    "cwe": {"type": "string"},
                    "owasp": {"type": "string"},
                    "description": {"type": "string"},
                    "reproduction": {"type": "string",
                                     "description": "Steps + observed evidence."},
                    "remediation": {"type": "string"},
                    "hypothesis_id": {"type": "integer",
                                      "description": "Linked hypothesis, if any."},
                },
                "required": ["title", "status", "severity", "description"],
            },
        },
        {
            "name": "record_attack_path",
            "description": (
                "Chain findings into an attack path. Only do this when the evidence "
                "supports EVERY step. Each step should cite a finding_id you already "
                "recorded (prefer confirmed findings) and describe the action it "
                "enables. Use for narratives like 'IDOR leaks token -> reuse token "
                "-> admin access'."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string",
                                    "description": "What the chain achieves overall."},
                    "severity": {"type": "string",
                                 "enum": ["info", "low", "medium", "high", "critical"]},
                    "mitre": {"type": "string",
                              "description": "Optional MITRE ATT&CK technique IDs, "
                                             "e.g. 'T1190, T1552'."},
                    "steps": {
                        "type": "array",
                        "description": "Ordered steps. Each cites evidence.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {"type": "string",
                                           "description": "What the attacker does."},
                                "finding_id": {"type": "integer",
                                               "description": "Finding this step relies on."},
                                "evidence": {"type": "string",
                                             "description": "Observed evidence for the step."},
                            },
                            "required": ["action"],
                        },
                    },
                },
                "required": ["title", "steps"],
            },
        },
        {
            "name": "set_phase",
            "description": "Set the current assessment phase (drives progress tracking).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "phase": {"type": "string", "enum": PHASE_ORDER},
                },
                "required": ["phase"],
            },
        },
        {
            "name": "conclude",
            "description": (
                "End the assessment. Call this when the objective is reasonably "
                "covered or further testing would exceed authorization."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string",
                                "description": "Brief professional summary of results."},
                },
                "required": ["summary"],
            },
        },
    ]


@dataclass
class DispatchResult:
    content: str          # JSON string returned to the model as the tool_result
    is_error: bool = False
    concluded: bool = False
    summary: str = ""


class ToolDispatcher:
    """Executes a single tool_use block and returns a tool_result payload."""

    def __init__(self, router: CapabilityRouter, db: Database, run_id: int):
        self.router = router
        self.db = db
        self.run_id = run_id
        # Simple telemetry the engine can surface.
        self.capability_calls = 0
        self.findings_recorded = 0

    def dispatch(self, name: str, tool_input: dict[str, Any]) -> DispatchResult:
        handler = getattr(self, f"_do_{name}", None)
        if handler is None:
            return DispatchResult(json.dumps({"error": f"unknown tool {name}"}),
                                  is_error=True)
        try:
            return handler(tool_input)
        except Exception as e:  # never crash the loop on a tool error
            return DispatchResult(json.dumps({"error": f"{type(e).__name__}: {e}"}),
                                  is_error=True)

    # ---- handlers -----------------------------------------------------

    def _do_request_capability(self, inp: dict) -> DispatchResult:
        self.capability_calls += 1
        request = CapabilityRequest(
            capability=inp["capability"],
            target=inp["target"],
            params=inp.get("params") or {},
            run_id=self.run_id,
            reason=inp.get("reason", ""),
        )
        outcome = self.router.run(request)

        payload: dict[str, Any] = {
            "capability": request.capability,
            "target": request.target,
            "ok": outcome.ok,
        }
        if outcome.blocked_by_scope:
            payload["blocked"] = "scope"
            payload["reason"] = outcome.reason
            return DispatchResult(json.dumps(payload))
        if outcome.result is None:
            payload["blocked"] = "policy_or_plugin"
            payload["reason"] = outcome.reason
            return DispatchResult(json.dumps(payload))

        res = outcome.result
        payload["plugin"] = res.plugin
        payload["return_code"] = res.return_code
        if res.error:
            payload["note"] = res.error
        payload["observations"] = [
            {"kind": o.kind, "summary": o.summary, "data": o.data}
            for o in res.observations
        ]
        return DispatchResult(json.dumps(payload), is_error=not outcome.ok)

    def _do_record_hypothesis(self, inp: dict) -> DispatchResult:
        hid = self.db.add_hypothesis(
            self.run_id, statement=inp["statement"],
            rationale=inp.get("rationale", ""), cwe=inp.get("cwe", ""),
            owasp=inp.get("owasp", ""), confidence=inp.get("confidence"),
        )
        return DispatchResult(json.dumps({"hypothesis_id": hid, "recorded": True}))

    def _do_record_finding(self, inp: dict) -> DispatchResult:
        status = inp["status"]
        # Enforce validation discipline: a confirmed finding must cite reproduction.
        if status == "confirmed" and not (inp.get("reproduction") or "").strip():
            return DispatchResult(json.dumps({
                "rejected": True,
                "reason": ("A 'confirmed' finding requires a reproduction field "
                           "citing observed evidence. Downgrade to 'possible' or "
                           "add reproduction."),
            }), is_error=True)
        fid = self.db.add_finding(
            self.run_id, title=inp["title"], status=status,
            severity=inp.get("severity", "info"), cvss_score=inp.get("cvss_score"),
            cvss_vector=inp.get("cvss_vector", ""), cwe=inp.get("cwe", ""),
            owasp=inp.get("owasp", ""), description=inp.get("description", ""),
            reproduction=inp.get("reproduction", ""),
            remediation=inp.get("remediation", ""),
            hypothesis_id=inp.get("hypothesis_id"),
        )
        self.findings_recorded += 1
        return DispatchResult(json.dumps({"finding_id": fid, "recorded": True,
                                          "status": status}))

    def _do_record_attack_path(self, inp: dict) -> DispatchResult:
        steps = inp.get("steps") or []
        if not steps:
            return DispatchResult(json.dumps({
                "rejected": True,
                "reason": "An attack path needs at least one step with evidence.",
            }), is_error=True)
        known = self.db.finding_ids(self.run_id)
        warnings = []
        for i, step in enumerate(steps, 1):
            fid = step.get("finding_id")
            if fid is None:
                if not (step.get("evidence") or "").strip():
                    warnings.append(f"step {i} cites neither a finding nor evidence")
            elif fid not in known:
                return DispatchResult(json.dumps({
                    "rejected": True,
                    "reason": f"step {i} references finding {fid}, which does not "
                              f"exist in this run. Record the finding first.",
                }), is_error=True)
            elif known[fid] != "confirmed":
                warnings.append(f"step {i} relies on finding {fid} which is "
                                f"'{known[fid]}', not confirmed")
        apid = self.db.add_attack_path(
            self.run_id, title=inp["title"], description=inp.get("description", ""),
            steps=steps, mitre=inp.get("mitre", ""),
            severity=inp.get("severity", "medium"),
        )
        payload = {"attack_path_id": apid, "recorded": True}
        if warnings:
            payload["warnings"] = warnings
        return DispatchResult(json.dumps(payload))

    def _do_set_phase(self, inp: dict) -> DispatchResult:
        phase = inp["phase"]
        self.db.set_run_phase(self.run_id, phase)
        return DispatchResult(json.dumps({"phase": phase, "set": True}))

    def _do_conclude(self, inp: dict) -> DispatchResult:
        summary = inp.get("summary", "")
        return DispatchResult(json.dumps({"concluded": True}),
                              concluded=True, summary=summary)
