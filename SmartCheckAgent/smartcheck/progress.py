"""Progress accounting + live display.

The percentage is derived from *actual completed assessment work*, not a timer.
It is a weighted blend of methodology-phase advancement and concrete coverage
(endpoints tested vs. discovered), persisted so a run can resume.
"""
from __future__ import annotations

from dataclasses import dataclass

from .db import Database

# PTES-aligned phases, in order, each contributing a share of overall progress.
# Weights sum to 1.0. Early phases are cheaper; testing/reporting dominate.
PHASES = [
    ("recon", 0.10),             # Intelligence gathering
    ("enumeration", 0.15),       # Service / content discovery
    ("vuln_analysis", 0.20),     # Hypothesis generation
    ("exploitation", 0.25),      # Authorization / vuln testing
    ("post_validation", 0.20),   # Reproduce + confirm findings
    ("reporting", 0.10),         # Report generation
]
PHASE_ORDER = [p[0] for p in PHASES]
PHASE_WEIGHT = dict(PHASES)


@dataclass
class ProgressSnapshot:
    percent: float
    phase: str
    endpoints_total: int
    endpoints_done: int
    tests_count: int
    confirmed_findings: int


def _phase_index(phase: str) -> int:
    try:
        return PHASE_ORDER.index(phase)
    except ValueError:
        return 0


# The step-budget "creep" fills at most this fraction of the room remaining in
# the current phase, so effort advances the bar every step but never completes a
# phase on its own — the last sliver is reserved for real coverage / the phase
# transition. Keeping it < 1 is what guarantees "steps alone never imply done".
_STEP_CREEP_FRACTION = 0.9


def compute(db: Database, run_id: int, step: int | None = None,
            max_steps: int | None = None) -> ProgressSnapshot:
    """Compute a progress snapshot from persisted knowledge.

    When `step`/`max_steps` are given (during an assess run), the reasoning-loop
    budget is blended in so the bar advances smoothly between phase transitions
    instead of sitting still. Progress is kept monotonic (never decreases).
    """
    run = db.get_run(run_id)
    phase = run["phase"] if run else "recon"

    endpoints_total = db.count("endpoints", run_id)
    endpoints_done = db.count("endpoints", run_id, "tested=1")
    tests_count = db.count("tests", run_id)
    confirmed = db.count_confirmed_findings(run_id)

    # Completed phases contribute their full weight.
    idx = _phase_index(phase)
    base = sum(PHASE_WEIGHT[p] for p in PHASE_ORDER[:idx])

    # Measured coverage of the current phase from real knowledge, in [0,1]. The
    # vuln-analysis/exploitation/validation phases progress as more of the
    # discovered attack surface is actually tested (tested endpoints / discovered
    # endpoints); enumeration by how much surface has been discovered; reporting
    # is terminal. Anything not yet measurable stays 0 and lets the step creep
    # (below) drive — so the bar is NOT dependent on normalization to keep moving.
    cur_weight = PHASE_WEIGHT.get(phase, 0.0)
    if phase in ("vuln_analysis", "exploitation", "post_validation") and endpoints_total > 0:
        measured = min(1.0, endpoints_done / endpoints_total)
    elif phase == "enumeration":
        measured = min(1.0, endpoints_total / 10.0) if endpoints_total else 0.0
    elif phase == "reporting":
        measured = 1.0
    else:
        measured = 0.0

    earned = base + cur_weight * measured           # real progress (fraction)

    # Step-budget creep: fill a fraction of the room still remaining in the
    # CURRENT phase, proportional to how far through the reasoning-loop budget we
    # are. Because `effort` rises on every step, the bar advances on every step
    # even before any coverage is measurable (the original "stuck" bug). It is
    # bounded to the current phase's ceiling, so steps can never imply a phase
    # that hasn't started is done, and the reserved sliver (CREEP_FRACTION < 1)
    # keeps effort alone from ever filling a phase.
    if step and max_steps:
        effort = min(1.0, step / max_steps)
        phase_ceiling = base + cur_weight
        earned += max(0.0, phase_ceiling - earned) * effort * _STEP_CREEP_FRACTION

    percent = earned * 100

    # Monotonic: never let a later recompute (e.g. from `status`, which has no
    # step context) drag the displayed progress backward.
    prev = db.get_progress(run_id)
    if prev and prev["percent"] is not None:
        percent = max(percent, prev["percent"])

    percent = round(max(0.0, min(100.0, percent)), 1)

    snap = ProgressSnapshot(percent, phase, endpoints_total, endpoints_done,
                            tests_count, confirmed)
    db.update_progress(run_id, percent, phase, endpoints_total, endpoints_done,
                       tests_count, confirmed)
    return snap


def bar(percent: float, width: int = 28) -> str:
    filled = int(round(width * percent / 100.0))
    return "[" + "█" * filled + "░" * (width - filled) + "]"


# Human-friendly phase labels for display.
_PHASE_LABELS = {
    "recon": "Reconnaissance",
    "enumeration": "Enumeration",
    "vuln_analysis": "Vulnerability Analysis",
    "exploitation": "Authorization Testing",
    "post_validation": "Validation",
    "reporting": "Reporting",
}


def render(snap: ProgressSnapshot) -> str:
    label = _PHASE_LABELS.get(snap.phase, snap.phase.title())
    lines = [
        f"{bar(snap.percent)} {snap.percent:.0f}%",
        "",
        f"Current phase: {label}",
        f"Endpoints: {snap.endpoints_done}/{snap.endpoints_total}",
        f"Tests: {snap.tests_count}",
        f"Confirmed findings: {snap.confirmed_findings}",
    ]
    return "\n".join(lines)
