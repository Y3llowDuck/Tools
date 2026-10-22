"""Domain model: enums and lightweight dataclasses shared across the agent.

These mirror the SQLite schema in db.py but stay free of persistence concerns,
so plugins and the (future) reasoning engine can pass them around cheaply.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ExecutionType(str, Enum):
    """How a plugin is driven."""
    ONE_SHOT = "one_shot"       # run once, collect output, done (nmap, curl, feroxbuster)
    INTERACTIVE = "interactive"  # long-lived session (Penelope reverse-shell handler)


class SafetyLevel(str, Enum):
    """Intrusiveness of a capability. Used to gate what the agent may do.

    Ordered least -> most intrusive. The executor and (later) the reasoning
    engine use this to require explicit opt-in for higher levels.
    """
    PASSIVE = "passive"      # read-only, no packets that change target state (e.g. a single GET)
    ACTIVE = "active"        # normal scanning / enumeration (nmap, feroxbuster)
    INTRUSIVE = "intrusive"  # may alter state or be noisy (auth attempts, uploads)
    DANGEROUS = "dangerous"  # never auto-run; shells, anything state-changing by design

    @property
    def rank(self) -> int:
        order = [SafetyLevel.PASSIVE, SafetyLevel.ACTIVE,
                 SafetyLevel.INTRUSIVE, SafetyLevel.DANGEROUS]
        return order.index(self)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    POSSIBLE = "possible"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


@dataclass
class CapabilityRequest:
    """What the reasoning engine (or CLI) asks for.

    It names a *capability*, never a command. The registry maps it to a plugin,
    and the plugin turns `params` into a validated argv for the executor.
    """
    capability: str
    target: str                                  # IP, host, or URL
    params: dict[str, Any] = field(default_factory=dict)
    run_id: Optional[int] = None
    reason: str = ""                             # why the engine wants this (for audit)
    # Filled in by the router from scope before dispatch, so port-scanning plugins
    # can default to the authorized port set instead of a broad default.
    scope_allowed_ports: Optional[set] = None


@dataclass
class ValidationResult:
    ok: bool
    reason: str = ""
    # argv the plugin intends to run; surfaced so it can be logged/shown before exec.
    argv: Optional[list[str]] = None


@dataclass
class Observation:
    """A single normalized fact parsed from tool output.

    `kind` is a short machine label (e.g. "open_port", "http_status",
    "discovered_path"); `data` holds structured fields.
    """
    kind: str
    data: dict[str, Any]
    summary: str = ""


@dataclass
class ExecutionResult:
    """What a plugin returns after running a capability."""
    ok: bool
    capability: str
    plugin: str
    argv: list[str]
    return_code: Optional[int] = None
    observations: list[Observation] = field(default_factory=list)
    raw_output: str = ""          # retained for evidence
    raw_stderr: str = ""
    evidence_path: Optional[str] = None
    error: str = ""
    duration_seconds: float = 0.0
