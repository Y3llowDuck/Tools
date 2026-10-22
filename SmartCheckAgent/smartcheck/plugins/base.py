"""Plugin interface.

Every tool integration implements this contract. The engine only ever sees
capabilities + this interface, so new tools drop in without engine changes.

Required surface (per spec):
    name, capabilities, execution_type, safety_level, validate(), execute(), parse()
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from ..models import (CapabilityRequest, ExecutionResult, ExecutionType,
                      Observation, SafetyLevel, ValidationResult)

if TYPE_CHECKING:
    from ..executor import SafeExecutor


class Plugin(ABC):
    """Base class for ONE_SHOT tools (nmap, curl, feroxbuster, ...)."""

    #: unique short name, e.g. "nmap"
    name: str = ""
    #: capabilities this plugin provides, e.g. ["network_discovery"]
    capabilities: list[str] = []
    #: ONE_SHOT or INTERACTIVE
    execution_type: ExecutionType = ExecutionType.ONE_SHOT
    #: default intrusiveness; a specific request may be refused if it exceeds policy
    safety_level: SafetyLevel = SafetyLevel.ACTIVE
    #: underlying binary name resolved via shutil.which
    binary: str = ""
    #: return codes that count as a successful run for this tool
    acceptable_return_codes: set[int] = {0}
    #: max wall-clock seconds for one run of this tool. None = use the executor
    #: default (the scope's request timeout). Scanners (nuclei, feroxbuster) need
    #: more than a single HTTP request timeout, so they raise this.
    execution_timeout: Optional[int] = None

    # ---- lifecycle -----------------------------------------------------

    def provides(self, capability: str) -> bool:
        return capability in self.capabilities

    def resolve_binary(self) -> Optional[str]:
        """Absolute path to this plugin's binary, or None if not on PATH.

        Plugins whose binary name is ambiguous (e.g. ProjectDiscovery httpx vs.
        the Python httpx CLI) override this to disambiguate.
        """
        import shutil
        return shutil.which(self.binary) if self.binary else None

    def available(self) -> bool:
        """Whether this plugin can run on this host. Registry uses this."""
        return True if not self.binary else self.resolve_binary() is not None

    @abstractmethod
    def build_argv(self, request: CapabilityRequest) -> list[str]:
        """Translate a validated request into an argv list (no shell)."""

    def ports_for(self, request: CapabilityRequest):
        """Concrete ports this request will touch, for scope enforcement.

        Returns a set[int], or None when the request is host-level / unknown.
        Default: the port embedded in the target (URL or host:port) plus an
        explicit `port` param. Port-scanning plugins (nmap) override this.
        """
        from ..scope import _split_target
        ports = set()
        _, parsed_port = _split_target(request.target)
        if parsed_port is not None:
            ports.add(int(parsed_port))
        p = request.params.get("port")
        if p is not None:
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                pass
        return ports or None

    @abstractmethod
    def validate(self, request: CapabilityRequest) -> ValidationResult:
        """Deterministically check params for this capability.

        Scope is validated separately upstream; this checks param sanity and
        builds the argv so it can be shown before execution.
        """

    @abstractmethod
    def parse(self, raw_stdout: str, raw_stderr: str,
              request: CapabilityRequest) -> list[Observation]:
        """Normalize raw tool output into structured observations."""

    # ---- execution (shared) -------------------------------------------

    def execute(self, request: CapabilityRequest,
                executor: "SafeExecutor") -> ExecutionResult:
        """Validate, run via the safe executor, and parse. Shared by all one-shots."""
        validation = self.validate(request)
        if not validation.ok:
            return ExecutionResult(
                ok=False, capability=request.capability, plugin=self.name,
                argv=validation.argv or [], error=validation.reason,
            )
        argv = validation.argv or self.build_argv(request)
        raw = executor.run(argv, timeout=self.execution_timeout,
                           label=f"{self.name}-{request.capability}")
        observations: list[Observation] = []
        error = ""
        rc_ok = raw.return_code in self.acceptable_return_codes
        if raw.return_code == 127:
            error = raw.stderr
        elif not rc_ok:
            # Surface the tool's own error so the failure is auditable, and still
            # parse whatever output exists (may yield partial observations).
            error = (raw.stderr.strip().splitlines() or ["non-zero exit"])[0]
            error = f"{self.binary} exited {raw.return_code}: {error}"
            try:
                observations = self.parse(raw.stdout, raw.stderr, request)
            except Exception:
                pass
        else:
            try:
                observations = self.parse(raw.stdout, raw.stderr, request)
            except Exception as e:  # parsing must never crash the agent
                error = f"parse error: {e}"
        return ExecutionResult(
            ok=rc_ok and not error,
            capability=request.capability, plugin=self.name, argv=argv,
            return_code=raw.return_code, observations=observations,
            raw_output=raw.stdout, raw_stderr=raw.stderr,
            evidence_path=raw.evidence_path, error=error,
            duration_seconds=raw.duration_seconds,
        )
