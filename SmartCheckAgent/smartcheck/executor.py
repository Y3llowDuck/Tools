"""Safe command executor.

The ONLY place in the agent that spawns external processes. It accepts an argv
list (never a shell string), enforces timeouts, rate limiting, a concurrency
cap, and a global kill switch, and persists raw output to disk for evidence.

Plugins build the argv; they never call subprocess themselves. This keeps a
single, auditable chokepoint between the agent's reasoning and the real tools.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import config


class KillSwitchError(Exception):
    """Raised when execution is attempted while the kill switch is engaged."""


@dataclass
class RawResult:
    return_code: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    evidence_path: Optional[str]
    argv: list[str]


class RateLimiter:
    """Simple global min-interval limiter (requests per second)."""

    def __init__(self, requests_per_second: float):
        self._min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self._min_interval:
                time.sleep(self._min_interval - delta)
            self._last = time.monotonic()


class SafeExecutor:
    def __init__(self, requests_per_second: float, timeout_seconds: int,
                 max_concurrency: int, evidence_dir: Optional[Path] = None,
                 kill_switch_path: Optional[Path] = None):
        self.default_timeout = timeout_seconds
        self.rate_limiter = RateLimiter(requests_per_second)
        self.semaphore = threading.Semaphore(max(1, max_concurrency))
        self.evidence_dir = Path(evidence_dir) if evidence_dir else config.EVIDENCE_DIR
        self.kill_switch_path = (Path(kill_switch_path) if kill_switch_path
                                 else config.KILL_SWITCH_PATH)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    # ---- kill switch ---------------------------------------------------

    def kill_switch_engaged(self) -> bool:
        return self.kill_switch_path.exists()

    def engage_kill_switch(self) -> None:
        self.kill_switch_path.parent.mkdir(parents=True, exist_ok=True)
        self.kill_switch_path.write_text(f"engaged {time.time()}\n")

    def release_kill_switch(self) -> None:
        if self.kill_switch_path.exists():
            self.kill_switch_path.unlink()

    # ---- execution -----------------------------------------------------

    @staticmethod
    def resolve_binary(name: str) -> Optional[str]:
        return shutil.which(name)

    def run(self, argv: list[str], timeout: Optional[int] = None,
            save_evidence: bool = True, label: str = "",
            stdin_data: Optional[str] = None) -> RawResult:
        """Execute argv with shell=False under all safety controls."""
        if not argv:
            raise ValueError("Empty argv.")
        if self.kill_switch_engaged():
            raise KillSwitchError(
                f"Kill switch engaged ({self.kill_switch_path}); refusing to execute."
            )

        timeout = timeout or self.default_timeout
        self.rate_limiter.wait()

        acquired = self.semaphore.acquire(timeout=max(timeout, 1) + 5)
        if not acquired:
            return RawResult(None, "", "concurrency slot unavailable", False, 0.0,
                             None, argv)
        start = time.monotonic()
        timed_out = False
        try:
            try:
                proc = subprocess.run(
                    argv,
                    input=stdin_data,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    shell=False,            # never a shell; argv only
                    check=False,
                )
                rc, out, err = proc.returncode, proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as e:
                timed_out = True
                rc = None
                out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
                err = (e.stderr.decode() if isinstance(e.stderr, bytes)
                       else (e.stderr or "")) + f"\n[timed out after {timeout}s]"
            except FileNotFoundError:
                return RawResult(127, "", f"binary not found: {argv[0]}", False,
                                 time.monotonic() - start, None, argv)
        finally:
            self.semaphore.release()
        duration = time.monotonic() - start

        evidence_path = None
        if save_evidence:
            evidence_path = self._save_evidence(argv, rc, out, err, label)

        return RawResult(rc, out, err, timed_out, duration, evidence_path, argv)

    def _save_evidence(self, argv: list[str], rc, out: str, err: str,
                       label: str) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        token = uuid.uuid4().hex[:8]
        safe_label = (label or Path(argv[0]).name).replace("/", "_")
        path = self.evidence_dir / f"{stamp}-{safe_label}-{token}.txt"
        header = (
            f"# command: {' '.join(argv)}\n"
            f"# return_code: {rc}\n"
            f"# timestamp: {stamp}\n"
            f"{'-' * 60}\n"
        )
        path.write_text(header + "## STDOUT\n" + out + "\n## STDERR\n" + err)
        return str(path)

    @classmethod
    def from_limits(cls, limits) -> "SafeExecutor":
        return cls(
            requests_per_second=limits.requests_per_second,
            timeout_seconds=limits.request_timeout_seconds,
            max_concurrency=limits.max_concurrency,
        )
