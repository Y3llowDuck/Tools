"""SQLite persistence: schema + a thin data-access layer.

Stores the agent's knowledge (assets, services, endpoints, parameters,
identities, tests, observations, hypotheses, findings, relationships,
attack_paths, plugins, progress) plus runs. Raw tool output is retained on disk
(see executor/evidence) and referenced here for evidence integrity.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from . import config

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT,
    scope_path  TEXT,
    status      TEXT DEFAULT 'active',      -- active | paused | completed | aborted
    phase       TEXT DEFAULT 'recon',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    kind        TEXT,                        -- host | network | domain
    value       TEXT NOT NULL,               -- ip / hostname / cidr
    label       TEXT,
    metadata    TEXT,                        -- json
    created_at  TEXT NOT NULL,
    UNIQUE(run_id, value)
);

CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    asset_id    INTEGER REFERENCES assets(id),
    port        INTEGER,
    protocol    TEXT,                        -- tcp | udp
    name        TEXT,                        -- http, ssh, ...
    product     TEXT,
    version     TEXT,
    state       TEXT,                        -- open | closed | filtered
    metadata    TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE(run_id, asset_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    service_id  INTEGER REFERENCES services(id),
    url         TEXT NOT NULL,
    method      TEXT DEFAULT 'GET',
    status_code INTEGER,
    content_type TEXT,
    content_length INTEGER,
    tested      INTEGER DEFAULT 0,           -- 0/1 used for progress accounting
    metadata    TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE(run_id, url, method)
);

CREATE TABLE IF NOT EXISTS parameters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    endpoint_id INTEGER REFERENCES endpoints(id),
    name        TEXT NOT NULL,
    location    TEXT,                        -- query | body | header | path | cookie
    example     TEXT,
    metadata    TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    kind        TEXT,                        -- credential | token | cookie | user
    label       TEXT,
    value_ref   TEXT,                        -- reference, NOT the secret itself
    metadata    TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    capability  TEXT NOT NULL,
    plugin      TEXT,
    target      TEXT,
    argv        TEXT,                        -- json list, for audit
    status      TEXT,                        -- ok | error | blocked
    return_code INTEGER,
    reason      TEXT,
    evidence_path TEXT,
    duration_seconds REAL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    test_id     INTEGER REFERENCES tests(id),
    kind        TEXT NOT NULL,
    summary     TEXT,
    data        TEXT,                        -- json
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    statement   TEXT NOT NULL,
    rationale   TEXT,
    status      TEXT DEFAULT 'open',         -- open | testing | supported | refuted
    cwe         TEXT,
    owasp       TEXT,
    confidence  REAL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    hypothesis_id INTEGER REFERENCES hypotheses(id),
    title       TEXT NOT NULL,
    status      TEXT NOT NULL,               -- possible | confirmed | false_positive
    severity    TEXT,                        -- info..critical
    cvss_score  REAL,
    cvss_vector TEXT,
    cwe         TEXT,
    owasp       TEXT,
    description TEXT,
    reproduction TEXT,
    remediation TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relationships (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    src_type    TEXT, src_id INTEGER,
    dst_type    TEXT, dst_id INTEGER,
    relation    TEXT,
    metadata    TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_paths (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES runs(id),
    title       TEXT NOT NULL,
    description TEXT,
    steps       TEXT,                        -- json ordered list of finding/observation refs
    mitre       TEXT,
    severity    TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugins (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT UNIQUE NOT NULL,
    capabilities TEXT,                       -- json list
    execution_type TEXT,
    safety_level TEXT,
    binary_path  TEXT,
    version      TEXT,
    status       TEXT DEFAULT 'active',      -- active | pending | disabled
    source       TEXT DEFAULT 'builtin',     -- builtin | generated
    metadata     TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS progress (
    run_id      INTEGER PRIMARY KEY REFERENCES runs(id),
    percent     REAL DEFAULT 0,
    phase       TEXT,
    endpoints_total INTEGER DEFAULT 0,
    endpoints_done  INTEGER DEFAULT 0,
    tests_count     INTEGER DEFAULT 0,
    confirmed_findings INTEGER DEFAULT 0,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_obs_run ON observations(run_id);
CREATE INDEX IF NOT EXISTS idx_tests_run ON tests(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_run ON endpoints(run_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else config.DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")

    # ---- lifecycle -----------------------------------------------------

    def init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        self.set_meta("schema_version", str(SCHEMA_VERSION))
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ---- meta ----------------------------------------------------------

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    # ---- runs ----------------------------------------------------------

    def create_run(self, name: str, scope_path: str) -> int:
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO runs(name, scope_path, created_at, updated_at) VALUES(?,?,?,?)",
            (name, scope_path, now, now),
        )
        rid = cur.lastrowid
        self._conn.execute(
            "INSERT INTO progress(run_id, phase, updated_at) VALUES(?,?,?)",
            (rid, "recon", now),
        )
        self._conn.commit()
        return rid

    def get_run(self, run_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()

    def latest_run(self) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def list_runs(self) -> list[sqlite3.Row]:
        return self._conn.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()

    def set_run_phase(self, run_id: int, phase: str) -> None:
        self._conn.execute(
            "UPDATE runs SET phase=?, updated_at=? WHERE id=?", (phase, _now(), run_id)
        )
        self._conn.commit()

    def set_run_status(self, run_id: int, status: str) -> None:
        """status: active | paused | completed | aborted."""
        self._conn.execute(
            "UPDATE runs SET status=?, updated_at=? WHERE id=?",
            (status, _now(), run_id),
        )
        self._conn.commit()

    # ---- knowledge writes ---------------------------------------------

    def add_asset(self, run_id: int, kind: str, value: str,
                  label: str = "", metadata: Optional[dict] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO assets(run_id,kind,value,label,metadata,created_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(run_id,value) DO UPDATE SET "
            "label=COALESCE(NULLIF(excluded.label,''), assets.label) "
            "RETURNING id",
            (run_id, kind, value, label, json.dumps(metadata or {}), _now()),
        )
        # Consume the RETURNING row before committing: committing while the
        # statement still has an unfetched row raises "SQL statements in progress".
        row = cur.fetchone()
        self._conn.commit()
        return row["id"]

    def add_service(self, run_id: int, asset_id: int, port: int, protocol: str,
                    name: str = "", product: str = "", version: str = "",
                    state: str = "open", metadata: Optional[dict] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO services(run_id,asset_id,port,protocol,name,product,version,"
            "state,metadata,created_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id,asset_id,port,protocol) DO UPDATE SET "
            # Don't let a later, less-specific sighting (e.g. an endpoint probe
            # that only knows the scheme) blank out richer data from nmap -sV.
            "name=COALESCE(NULLIF(excluded.name,''), services.name), "
            "product=COALESCE(NULLIF(excluded.product,''), services.product), "
            "version=COALESCE(NULLIF(excluded.version,''), services.version), "
            "state=COALESCE(NULLIF(excluded.state,''), services.state) RETURNING id",
            (run_id, asset_id, port, protocol, name, product, version, state,
             json.dumps(metadata or {}), _now()),
        )
        row = cur.fetchone()
        self._conn.commit()
        return row["id"]

    def add_endpoint(self, run_id: int, url: str, method: str = "GET",
                     service_id: Optional[int] = None, status_code: Optional[int] = None,
                     content_type: str = "", content_length: Optional[int] = None,
                     tested: int = 0, metadata: Optional[dict] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO endpoints(run_id,service_id,url,method,status_code,content_type,"
            "content_length,tested,metadata,created_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id,url,method) DO UPDATE SET "
            # Never overwrite a known value with a NULL/blank from a later, less
            # informative sighting; `tested` is sticky (once tested, stays tested).
            "status_code=COALESCE(excluded.status_code, endpoints.status_code), "
            "content_type=COALESCE(NULLIF(excluded.content_type,''), endpoints.content_type), "
            "content_length=COALESCE(excluded.content_length, endpoints.content_length), "
            "service_id=COALESCE(excluded.service_id, endpoints.service_id), "
            "tested=MAX(endpoints.tested, excluded.tested) RETURNING id",
            (run_id, service_id, url, method, status_code, content_type,
             content_length, int(tested), json.dumps(metadata or {}), _now()),
        )
        row = cur.fetchone()
        self._conn.commit()
        return row["id"]

    def add_parameter(self, run_id: int, endpoint_id: Optional[int], name: str,
                      location: str = "query", example: str = "",
                      metadata: Optional[dict] = None) -> int:
        """Record a request parameter, de-duplicated per (endpoint, name, location).

        The parameters table has no UNIQUE constraint (a parameter may legitimately
        recur), so dedup is done here to keep normalization idempotent.
        """
        row = self._conn.execute(
            "SELECT id FROM parameters WHERE run_id=? AND endpoint_id IS ? "
            "AND name=? AND location=?",
            (run_id, endpoint_id, name, location),
        ).fetchone()
        if row:
            return row["id"]
        cur = self._conn.execute(
            "INSERT INTO parameters(run_id,endpoint_id,name,location,example,metadata,"
            "created_at) VALUES(?,?,?,?,?,?,?)",
            (run_id, endpoint_id, name, location, example,
             json.dumps(metadata or {}), _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def record_test(self, run_id: int, capability: str, plugin: str, target: str,
                    argv: list[str], status: str, return_code: Optional[int],
                    reason: str = "", evidence_path: str = "",
                    duration_seconds: float = 0.0) -> int:
        cur = self._conn.execute(
            "INSERT INTO tests(run_id,capability,plugin,target,argv,status,return_code,"
            "reason,evidence_path,duration_seconds,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, capability, plugin, target, json.dumps(argv), status, return_code,
             reason, evidence_path, duration_seconds, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def add_hypothesis(self, run_id: int, statement: str, rationale: str = "",
                       cwe: str = "", owasp: str = "",
                       confidence: Optional[float] = None,
                       status: str = "open") -> int:
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO hypotheses(run_id,statement,rationale,status,cwe,owasp,"
            "confidence,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (run_id, statement, rationale, status, cwe, owasp, confidence, now, now),
        )
        self._conn.commit()
        return cur.lastrowid

    def set_hypothesis_status(self, hypothesis_id: int, status: str) -> None:
        self._conn.execute(
            "UPDATE hypotheses SET status=?, updated_at=? WHERE id=?",
            (status, _now(), hypothesis_id),
        )
        self._conn.commit()

    def add_finding(self, run_id: int, title: str, status: str, severity: str = "info",
                    cvss_score: Optional[float] = None, cvss_vector: str = "",
                    cwe: str = "", owasp: str = "", description: str = "",
                    reproduction: str = "", remediation: str = "",
                    hypothesis_id: Optional[int] = None) -> int:
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO findings(run_id,hypothesis_id,title,status,severity,cvss_score,"
            "cvss_vector,cwe,owasp,description,reproduction,remediation,created_at,"
            "updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, hypothesis_id, title, status, severity, cvss_score, cvss_vector,
             cwe, owasp, description, reproduction, remediation, now, now),
        )
        self._conn.commit()
        return cur.lastrowid

    def add_attack_path(self, run_id: int, title: str, description: str = "",
                        steps: Optional[list] = None, mitre: str = "",
                        severity: str = "medium") -> int:
        cur = self._conn.execute(
            "INSERT INTO attack_paths(run_id,title,description,steps,mitre,severity,"
            "created_at) VALUES(?,?,?,?,?,?,?)",
            (run_id, title, description, json.dumps(steps or []), mitre, severity,
             _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def finding_ids(self, run_id: int) -> dict[int, str]:
        """Map finding id -> status for this run (used to validate path steps)."""
        rows = self._conn.execute(
            "SELECT id, status FROM findings WHERE run_id=?", (run_id,)
        ).fetchall()
        return {r["id"]: r["status"] for r in rows}

    def add_observation(self, run_id: int, test_id: Optional[int], kind: str,
                        summary: str, data: dict) -> int:
        cur = self._conn.execute(
            "INSERT INTO observations(run_id,test_id,kind,summary,data,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (run_id, test_id, kind, summary, json.dumps(data), _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def upsert_plugin(self, name: str, capabilities: list[str], execution_type: str,
                      safety_level: str, binary_path: str = "", version: str = "",
                      status: str = "active", source: str = "builtin",
                      metadata: Optional[dict] = None) -> None:
        now = _now()
        self._conn.execute(
            "INSERT INTO plugins(name,capabilities,execution_type,safety_level,"
            "binary_path,version,status,source,metadata,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
            "capabilities=excluded.capabilities, execution_type=excluded.execution_type, "
            "safety_level=excluded.safety_level, binary_path=excluded.binary_path, "
            "version=excluded.version, status=excluded.status, updated_at=excluded.updated_at",
            (name, json.dumps(capabilities), execution_type, safety_level, binary_path,
             version, status, source, json.dumps(metadata or {}), now, now),
        )
        self._conn.commit()

    def list_plugins(self) -> list[sqlite3.Row]:
        return self._conn.execute("SELECT * FROM plugins ORDER BY name").fetchall()

    def delete_plugin(self, name: str) -> int:
        cur = self._conn.execute(
            "DELETE FROM plugins WHERE name=? AND source='generated'", (name,))
        self._conn.commit()
        return cur.rowcount

    # ---- progress ------------------------------------------------------

    def update_progress(self, run_id: int, percent: float, phase: str,
                        endpoints_total: int, endpoints_done: int,
                        tests_count: int, confirmed_findings: int) -> None:
        self._conn.execute(
            "INSERT INTO progress(run_id,percent,phase,endpoints_total,endpoints_done,"
            "tests_count,confirmed_findings,updated_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id) DO UPDATE SET percent=excluded.percent, "
            "phase=excluded.phase, endpoints_total=excluded.endpoints_total, "
            "endpoints_done=excluded.endpoints_done, tests_count=excluded.tests_count, "
            "confirmed_findings=excluded.confirmed_findings, updated_at=excluded.updated_at",
            (run_id, percent, phase, endpoints_total, endpoints_done, tests_count,
             confirmed_findings, _now()),
        )
        self._conn.commit()

    def get_progress(self, run_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM progress WHERE run_id=?", (run_id,)
        ).fetchone()

    # ---- counts used by progress calc ---------------------------------

    def count(self, table: str, run_id: int, where: str = "", params: tuple = ()) -> int:
        allowed = {"assets", "services", "endpoints", "parameters", "identities",
                   "tests", "observations", "hypotheses", "findings"}
        if table not in allowed:
            raise ValueError(f"count() not allowed on table {table!r}")
        sql = f"SELECT COUNT(*) AS n FROM {table} WHERE run_id=?"
        args: tuple = (run_id,)
        if where:
            sql += f" AND {where}"
            args += params
        return self._conn.execute(sql, args).fetchone()["n"]

    def count_confirmed_findings(self, run_id: int) -> int:
        return self.count("findings", run_id, "status='confirmed'")

    # ---- reads used by the summary ------------------------------------

    def observations(self, run_id: int, kind: Optional[str] = None) -> list[sqlite3.Row]:
        if kind:
            return self._conn.execute(
                "SELECT * FROM observations WHERE run_id=? AND kind=? ORDER BY id",
                (run_id, kind),
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM observations WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()

    def observation_kind_counts(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT kind, COUNT(*) AS n FROM observations WHERE run_id=? "
            "GROUP BY kind ORDER BY n DESC", (run_id,)
        ).fetchall()

    def tests(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM tests WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()

    def test_status_counts(self, run_id: int) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM tests WHERE run_id=? GROUP BY status",
            (run_id,),
        ).fetchall()
        return {r["status"]: r["n"] for r in rows}

    def blocked_tests(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM tests WHERE run_id=? AND status='blocked' ORDER BY id",
            (run_id,),
        ).fetchall()

    def findings(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM findings WHERE run_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
            (run_id,),
        ).fetchall()

    def hypotheses(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM hypotheses WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()

    def attack_paths(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM attack_paths WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()

    def capability_breakdown(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT capability, plugin, COUNT(*) AS n, "
            "SUM(COALESCE(duration_seconds,0)) AS total_seconds "
            "FROM tests WHERE run_id=? GROUP BY capability, plugin "
            "ORDER BY n DESC", (run_id,),
        ).fetchall()

    def tests_with_evidence(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM tests WHERE run_id=? AND evidence_path<>'' ORDER BY id",
            (run_id,),
        ).fetchall()
