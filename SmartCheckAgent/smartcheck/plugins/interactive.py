"""Interactive plugin interface for long-lived, stateful tools.

Penelope (reverse-shell handler) is the motivating example. These tools are not
run-once; they are started, polled, fed input, and stopped. The full driver for
Penelope arrives in a later increment; this defines the contract now so the
registry and engine can treat interactive plugins uniformly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..models import ExecutionType, Observation, SafetyLevel


@dataclass
class SessionEvent:
    kind: str                       # e.g. "connection", "output", "exit"
    data: dict[str, Any] = field(default_factory=dict)
    summary: str = ""


class InteractivePlugin(ABC):
    name: str = ""
    capabilities: list[str] = []
    execution_type: ExecutionType = ExecutionType.INTERACTIVE
    safety_level: SafetyLevel = SafetyLevel.DANGEROUS  # shells are never auto-run
    binary: str = ""

    def provides(self, capability: str) -> bool:
        return capability in self.capabilities

    @abstractmethod
    def start(self, params: dict[str, Any]) -> str:
        """Begin a session; return a session id."""

    @abstractmethod
    def status(self, session_id: str) -> str:
        """Return a status string: starting | listening | connected | closed."""

    @abstractmethod
    def get_events(self, session_id: str) -> list[SessionEvent]:
        """Drain and return new normalized events since the last call."""

    @abstractmethod
    def send_input(self, session_id: str, data: str) -> None:
        """Send input into the session (e.g. a shell command)."""

    @abstractmethod
    def stop(self, session_id: str) -> None:
        """Terminate the session and release resources."""

    def parse_event(self, event: SessionEvent) -> list[Observation]:
        """Optionally turn an event into observations. Default: none."""
        return []
