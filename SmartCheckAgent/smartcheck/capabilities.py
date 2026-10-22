"""Capability router.

This is the seam the (future) reasoning engine uses: it requests a *capability*,
and this module enforces the pipeline:

    scope check (deterministic) -> plugin select -> validate -> execute -> parse
        -> persist test + observations -> return normalized result

The reasoning model never sees a command and never reaches the executor directly.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from .db import Database
from .executor import KillSwitchError, SafeExecutor
from .models import CapabilityRequest, ExecutionResult, SafetyLevel
from .normalize import normalize
from .plugins.registry import Registry
from .scope import Scope


@dataclass
class CapabilityOutcome:
    ok: bool
    result: Optional[ExecutionResult]
    reason: str
    blocked_by_scope: bool = False
    test_id: Optional[int] = None


class CapabilityRouter:
    def __init__(self, scope: Scope, registry: Registry, executor: SafeExecutor,
                 db: Database, max_safety: SafetyLevel = SafetyLevel.ACTIVE):
        self.scope = scope
        self.registry = registry
        self.executor = executor
        self.db = db
        # Ceiling on auto-run intrusiveness. Anything above is refused here.
        self.max_safety = max_safety

    def _target_port(self, request: CapabilityRequest) -> Optional[int]:
        return request.params.get("port")

    def run(self, request: CapabilityRequest,
            prefer_plugin: Optional[str] = None) -> CapabilityOutcome:
        # 1. Deterministic scope gate — before anything else.
        decision = self.scope.check(request.target, self._target_port(request))
        if not decision.allowed:
            self._record_blocked(request, f"SCOPE DENIED: {decision.reason}")
            return CapabilityOutcome(
                ok=False, result=None,
                reason=f"Out of scope: {decision.reason}", blocked_by_scope=True,
            )

        # 2. Select a plugin for the capability.
        plugin = self.registry.select(request.capability, prefer=prefer_plugin)
        if plugin is None:
            reason = (f"No available plugin provides capability "
                      f"{request.capability!r}.")
            self._record_blocked(request, reason)
            return CapabilityOutcome(False, None, reason)

        # 3. Safety ceiling.
        if plugin.safety_level.rank > self.max_safety.rank:
            reason = (f"Capability requires safety level "
                      f"'{plugin.safety_level.value}' which exceeds the allowed "
                      f"ceiling '{self.max_safety.value}'.")
            self._record_blocked(request, reason)
            return CapabilityOutcome(False, None, reason)

        # 3b. Port-scope enforcement. Let the plugin default to authorized ports,
        # then deterministically reject any port the plugin would touch that is
        # outside the scope's allowed_ports.
        request.scope_allowed_ports = set(self.scope.allowed_ports) or None
        try:
            ports = plugin.ports_for(request)
        except Exception:
            ports = None
        if ports:
            ok_ports, bad = self.scope.check_ports(ports)
            if not ok_ports:
                reason = (f"Request would touch out-of-scope port(s) {bad}; "
                          f"allowed ports are {sorted(self.scope.allowed_ports)}.")
                self._record_blocked(request, reason)
                return CapabilityOutcome(False, None, reason, blocked_by_scope=True)

        # 4. Execute through the plugin (which validates + runs via executor).
        try:
            result = plugin.execute(request, self.executor)
        except KillSwitchError as e:
            self._record_blocked(request, str(e))
            return CapabilityOutcome(False, None, str(e))

        # 5. Persist the test + observations.
        test_id = self._persist(request, plugin.name, result)
        return CapabilityOutcome(
            ok=result.ok, result=result,
            reason=result.error or "ok", test_id=test_id,
        )

    # ---- persistence helpers ------------------------------------------

    def _persist(self, request: CapabilityRequest, plugin_name: str,
                 result: ExecutionResult) -> Optional[int]:
        if request.run_id is None:
            return None
        status = "ok" if result.ok else "error"
        test_id = self.db.record_test(
            run_id=request.run_id, capability=request.capability, plugin=plugin_name,
            target=request.target, argv=result.argv, status=status,
            return_code=result.return_code, reason=result.error,
            evidence_path=result.evidence_path or "",
            duration_seconds=result.duration_seconds,
        )
        for obs in result.observations:
            self.db.add_observation(request.run_id, test_id, obs.kind,
                                    obs.summary, obs.data)
        # Promote the facts in those observations into the structured knowledge
        # tables (assets/services/endpoints/parameters). Must never break a scan.
        try:
            normalize(self.db, request.run_id, request, result.observations)
        except Exception:
            pass
        return test_id

    def _record_blocked(self, request: CapabilityRequest, reason: str) -> None:
        if request.run_id is None:
            return
        self.db.record_test(
            run_id=request.run_id, capability=request.capability, plugin="",
            target=request.target, argv=[], status="blocked",
            return_code=None, reason=reason,
        )
