"""The reasoning loop: a manual Anthropic tool-use loop.

A manual loop (rather than the SDK tool runner) is used deliberately so every
capability call passes through our scope gate and persistence, and so the loop
has no beta dependency. The model is given tools only; it cannot run commands.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from .. import progress
from ..capabilities import CapabilityRouter
from ..db import Database
from ..executor import SafeExecutor
from ..models import SafetyLevel
from ..plugins.registry import Registry
from ..scope import Scope
from . import prompts
from .tools import ToolDispatcher, tool_definitions

# No hardcoded fallback: the model handles authorized security-testing tasks
# very differently release to release (some newer safety classifiers refuse
# them outright), so pin one explicitly rather than silently drifting onto a
# baked-in default. Required via --model or $SMARTCHECK_MODEL.
DEFAULT_MODEL = os.environ.get("SMARTCHECK_MODEL")


class EngineError(Exception):
    pass


@dataclass
class StepEvent:
    """Emitted after each loop step so the CLI can show live activity."""
    step: int
    kind: str                       # "thinking" | "tool" | "text" | "conclude" | "error"
    text: str = ""
    detail: dict = field(default_factory=dict)


@dataclass
class AssessmentResult:
    concluded: bool
    summary: str
    steps: int
    capability_calls: int
    findings_recorded: int
    stop_reason: str = ""


def _anthropic_client():
    try:
        import anthropic
    except ImportError as e:
        raise EngineError(
            "The 'anthropic' package is not installed. Activate the venv and run:\n"
            "  pip install anthropic\n"
            "(uncomment it in requirements.txt)."
        ) from e
    try:
        return anthropic.Anthropic()  # resolves key/profile from environment
    except Exception as e:  # noqa: BLE001
        raise EngineError(f"Could not initialize Anthropic client: {e}") from e


def build_resume_context(db: Database, run_id: int, limit: int = 15) -> Optional[str]:
    """Compact summary of what a run already knows, for resuming it.

    Returns None if there's no prior work. Kept bounded so it doesn't blow up
    the context window.
    """
    import json as _json

    if db.count("tests", run_id) == 0:
        return None
    run = db.get_run(run_id)
    lines = [f"You are RESUMING assessment run #{run_id} "
             f"(current phase: {run['phase'] if run else 'recon'}). "
             f"Here is what is ALREADY established — do not repeat this work:"]

    def _rows(kind):
        return db.observations(run_id, kind)

    def _d(o):
        try:
            return _json.loads(o["data"] or "{}")
        except (ValueError, TypeError):
            return {}

    ports = _rows("open_port")
    if ports:
        lines.append("Open ports/services: " + "; ".join(
            f"{_d(o).get('host')}:{_d(o).get('port')} {_d(o).get('service','')} "
            f"{_d(o).get('version','')}".strip() for o in ports[:limit]))
    techs = sorted({_d(o).get("technology", "") for o in _rows("technology")} - {""})
    if techs:
        lines.append("Technologies: " + ", ".join(techs))
    paths = _rows("discovered_path")
    if paths:
        lines.append(f"Discovered paths ({len(paths)}): " + ", ".join(
            str(_d(o).get("url")) for o in paths[:limit]))
    hyps = [h for h in db.hypotheses(run_id) if h["status"] in ("open", "testing")]
    if hyps:
        lines.append("Open hypotheses: " + " | ".join(
            f"[H{h['id']}] {h['statement']}" for h in hyps[:limit]))
    findings = db.findings(run_id)
    if findings:
        lines.append("Findings so far: " + " | ".join(
            f"[F{f['id']} {f['status']}/{f['severity']}] {f['title']}"
            for f in findings[:limit]))
    lines.append("Continue from here: pursue open hypotheses, validate what is "
                 "unproven, and investigate gaps. Do not re-run completed recon.")
    return "\n".join(lines)


class ReasoningEngine:
    def __init__(self, scope: Scope, registry: Registry, executor: SafeExecutor,
                 db: Database, run_id: int, max_safety: SafetyLevel,
                 model: str = DEFAULT_MODEL, max_steps: int = 40,
                 on_event: Optional[Callable[[StepEvent], None]] = None):
        self.scope = scope
        self.registry = registry
        self.db = db
        self.run_id = run_id
        self.max_safety = max_safety
        if not model:
            raise EngineError(
                "No model specified. Pass --model or set $SMARTCHECK_MODEL.")
        self.model = model
        self.max_steps = max_steps
        self.on_event = on_event or (lambda e: None)
        self.router = CapabilityRouter(scope, registry, executor, db,
                                       max_safety=max_safety)

    def _emit_progress(self, step: int, snap) -> None:
        self.on_event(StepEvent(step, "progress", "", {
            "percent": snap.percent,
            "phase": snap.phase,
            "tests": snap.tests_count,
            "endpoints_done": snap.endpoints_done,
            "endpoints_total": snap.endpoints_total,
            "confirmed": snap.confirmed_findings,
            "step": step,
            "max_steps": self.max_steps,
        }))

    def run(self, target: str, objective: str) -> AssessmentResult:
        client = _anthropic_client()
        available = self.registry.available_capabilities()
        capabilities = sorted(available.keys())
        if not capabilities:
            raise EngineError("No capabilities available (no usable plugins on PATH).")

        system = prompts.build_system_prompt(self.scope, available,
                                             self.max_safety.value)
        tools = tool_definitions(capabilities)
        dispatcher = ToolDispatcher(self.router, self.db, self.run_id)

        resume = build_resume_context(self.db, self.run_id)
        if resume:
            self.on_event(StepEvent(0, "text", f"Resuming run #{self.run_id} "
                                    f"with prior context."))
        user_kickoff = (
            f"AUTHORIZED ENGAGEMENT\n"
            f"Primary target: {target}\n"
            f"Objective: {objective}\n\n"
            + (resume + "\n\n" if resume else "")
            + ("Begin the assessment. " if not resume else "")
            + "Set the phase as you go, record hypotheses before testing, "
            "validate before confirming, and conclude when done."
        )
        messages: list[dict] = [{"role": "user", "content": user_kickoff}]

        concluded = False
        summary = ""
        stop_reason = ""
        step = 0

        while step < self.max_steps:
            step += 1
            try:
                response = client.messages.create(
                    model=self.model,
                    max_tokens=8000,
                    thinking={"type": "adaptive"},
                    system=system,
                    tools=tools,
                    messages=messages,
                )
            except Exception as e:  # noqa: BLE001
                msg = str(e)
                if ("authentication" in msg.lower() or "api_key" in msg.lower()
                        or "x-api-key" in msg.lower()):
                    raise EngineError(
                        "No Anthropic credentials found. Set one of:\n"
                        "  export ANTHROPIC_API_KEY=sk-ant-...\n"
                        "  (or run `ant auth login` if you use the Anthropic CLI)\n"
                        "then retry `agent.py assess`."
                    ) from e
                raise EngineError(f"Anthropic API call failed: {e}") from e

            stop_reason = response.stop_reason or ""

            if stop_reason == "refusal":
                detail = getattr(response, "stop_details", None)
                reason = getattr(detail, "explanation", "") if detail else ""
                self.on_event(StepEvent(step, "error",
                                        f"Model refused: {reason}"))
                break

            # Surface any assistant text and collect tool_use blocks.
            tool_uses = []
            for block in response.content:
                if block.type == "text" and block.text.strip():
                    self.on_event(StepEvent(step, "text", block.text.strip()))
                elif block.type == "tool_use":
                    tool_uses.append(block)

            # Append the assistant turn verbatim (preserves thinking + tool_use).
            messages.append({"role": "assistant", "content": response.content})

            if stop_reason != "tool_use" or not tool_uses:
                # The model ended its turn without requesting a tool: treat as done.
                concluded = concluded or (stop_reason == "end_turn")
                break

            # Execute every requested tool; collect results into one user message.
            tool_results = []
            for tu in tool_uses:
                if tu.name == "request_capability":
                    tgt = tu.input.get("target", "?")
                    cap = tu.input.get("capability", "?")
                    self.on_event(StepEvent(step, "tool",
                                            f"{cap} → {tgt}",
                                            {"capability": cap, "target": tgt}))
                else:
                    self.on_event(StepEvent(step, "tool", tu.name, dict(tu.input)))

                result = dispatcher.dispatch(tu.name, tu.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": result.content,
                    "is_error": result.is_error,
                })
                if result.concluded:
                    concluded = True
                    summary = result.summary

            messages.append({"role": "user", "content": tool_results})

            # Refresh persisted progress after each round of real work.
            snap = progress.compute(self.db, self.run_id, step=step,
                                    max_steps=self.max_steps)
            self._emit_progress(step, snap)

            if concluded:
                self.on_event(StepEvent(step, "conclude", summary))
                break

        if concluded:
            self.db.set_run_phase(self.run_id, "reporting")
            self.db.set_run_status(self.run_id, "completed")
        final_snap = progress.compute(self.db, self.run_id, step=step,
                                      max_steps=self.max_steps)
        self._emit_progress(step, final_snap)

        return AssessmentResult(
            concluded=concluded, summary=summary, steps=step,
            capability_calls=dispatcher.capability_calls,
            findings_recorded=dispatcher.findings_recorded,
            stop_reason=stop_reason,
        )
