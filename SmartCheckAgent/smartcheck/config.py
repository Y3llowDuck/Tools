"""Central configuration: paths and constants.

Nothing here reaches out to the network or executes tools; it only resolves
where things live on disk so every module agrees.
"""
from __future__ import annotations

import os
from pathlib import Path

# Project root = the directory that contains this package's parent.
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent

# Data directory holds the SQLite DB and raw tool evidence. Overridable for tests.
DATA_DIR = Path(os.environ.get("SMARTCHECK_DATA_DIR", PROJECT_ROOT / "data"))
DB_PATH = Path(os.environ.get("SMARTCHECK_DB", DATA_DIR / "smartcheck.db"))
EVIDENCE_DIR = DATA_DIR / "evidence"
# Declarative adapter specs for tools onboarded via `plugin add` live here.
GENERATED_PLUGINS_DIR = Path(
    os.environ.get("SMARTCHECK_PLUGINS_DIR", DATA_DIR / "plugins"))

# Scope file. Deny-by-default: if it is missing, nothing is in scope.
SCOPE_PATH = Path(os.environ.get("SMARTCHECK_SCOPE", PROJECT_ROOT / "scope.yaml"))
SCOPE_EXAMPLE_PATH = PROJECT_ROOT / "scope.example.yaml"

# Kill switch: presence of this file halts all new executions immediately.
KILL_SWITCH_PATH = Path(os.environ.get("SMARTCHECK_KILLSWITCH", DATA_DIR / ".kill"))

# Conservative defaults; scope.yaml `limits:` overrides these.
DEFAULT_REQUESTS_PER_SECOND = 5.0
DEFAULT_REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_MAX_CONCURRENCY = 3


def ensure_dirs() -> None:
    """Create runtime directories if absent. Safe to call repeatedly."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
