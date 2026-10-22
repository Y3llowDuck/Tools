"""Tests for the reasoning engine and tool dispatcher.

These run WITHOUT any Anthropic API key or network: the Anthropic client is
replaced with a scripted fake that drives the manual tool-use loop, so we verify
the loop mechanics, scope gating, persistence, and validation discipline for free.
"""
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolate DB + data to a temp dir before importing modules that read config.
_TMP = tempfile.mkdtemp(prefix="smartcheck-test-")
os.environ["SMARTCHECK_DATA_DIR"] = _TMP
os.environ["SMARTCHECK_DB"] = str(Path(_TMP) / "test.db")
os.environ["SMARTCHECK_KILLSWITCH"] = str(Path(_TMP) / ".kill")

from smartcheck import config  # noqa: E402
from smartcheck.db import Database  # noqa: E402
from smartcheck.executor import SafeExecutor  # noqa: E402
from smartcheck.models import SafetyLevel  # noqa: E402
from smartcheck.plugins.registry import Registry  # noqa: E402
from smartcheck.scope import Scope  # noqa: E402
from smartcheck.capabilities import CapabilityRouter  # noqa: E402
from smartcheck.reasoning import engine as engine_mod  # noqa: E402
from smartcheck.reasoning.tools import ToolDispatcher  # noqa: E402

SCOPE_YAML = """
authorization: {authorized_by: tester, engagement: unit-test}
targets:
  ips: [127.0.0.1]
ports: {allowed: [80, 8000]}
limits: {requests_per_second: 100, max_concurrency: 2}
"""


def _scope() -> Scope:
    p = Path(_TMP) / "scope.yaml"
    p.write_text(SCOPE_YAML)
    return Scope.load(p)


# ---- fake Anthropic client ------------------------------------------------

class _Block:
    def __init__(self, type, text="", id="", name="", input=None):
        self.type = type
        self.text = text
        self.id = id
        self.name = name
        self.input = input or {}


class _Response:
    def __init__(self, stop_reason, content):
        self.stop_reason = stop_reason
        self.content = content
        self.stop_details = None


class _Messages:
    def __init__(self, script):
        self._script = script
        self._i = 0

    def create(self, **kwargs):
        resp = self._script[self._i]
        self._i += 1
        return resp


class _FakeClient:
    def __init__(self, script):
        self.messages = _Messages(script)


def _tool_use(id, name, inp):
    return _Block("tool_use", id=id, name=name, input=inp)


# ---- dispatcher tests (no engine) ----------------------------------------

class TestDispatcher(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.db.init_schema()
        self.scope = _scope()
        self.reg = Registry.with_builtins()
        self.ex = SafeExecutor.from_limits(self.scope.limits)
        self.router = CapabilityRouter(self.scope, self.reg, self.ex, self.db,
                                       max_safety=SafetyLevel.ACTIVE)
        self.run_id = self.db.create_run("t", "scope.yaml")
        self.disp = ToolDispatcher(self.router, self.db, self.run_id)

    def tearDown(self):
        self.db.close()

    def test_request_capability_scope_block(self):
        r = self.disp.dispatch("request_capability", {
            "capability": "network_discovery", "target": "8.8.8.8",
            "reason": "test",
        })
        self.assertIn('"blocked": "scope"', r.content)

    def test_request_capability_out_of_scope_port_blocked(self):
        # scope allows ports {80, 8000}; nmap on 3306 must be blocked, not run.
        r = self.disp.dispatch("request_capability", {
            "capability": "network_discovery", "target": "127.0.0.1",
            "params": {"ports": "80,3306"}, "reason": "test",
        })
        self.assertIn('"blocked": "scope"', r.content)
        self.assertIn("3306", r.content)

    def test_confirmed_finding_requires_reproduction(self):
        r = self.disp.dispatch("record_finding", {
            "title": "SQLi", "status": "confirmed", "severity": "high",
            "description": "x", "reproduction": "",
        })
        self.assertTrue(r.is_error)
        self.assertIn("rejected", r.content)
        self.assertEqual(self.db.count("findings", self.run_id), 0)

    def test_possible_finding_recorded(self):
        r = self.disp.dispatch("record_finding", {
            "title": "Info leak", "status": "possible", "severity": "low",
            "description": "server banner exposed",
        })
        self.assertFalse(r.is_error)
        self.assertEqual(self.db.count("findings", self.run_id), 1)

    def test_confirmed_with_reproduction_recorded(self):
        r = self.disp.dispatch("record_finding", {
            "title": "Dir listing", "status": "confirmed", "severity": "medium",
            "description": "listing enabled", "reproduction": "GET /admin -> 200 lists files",
        })
        self.assertFalse(r.is_error)
        self.assertEqual(self.db.count("findings", self.run_id, "status='confirmed'"), 1)

    def test_attack_path_requires_existing_findings(self):
        # Unknown finding id is rejected.
        r = self.disp.dispatch("record_attack_path", {
            "title": "x", "steps": [{"action": "y", "finding_id": 999}]})
        self.assertTrue(r.is_error)
        self.assertIn("does not exist", r.content)

    def test_attack_path_empty_steps_rejected(self):
        r = self.disp.dispatch("record_attack_path", {"title": "x", "steps": []})
        self.assertTrue(r.is_error)

    def test_attack_path_recorded_with_valid_findings(self):
        fid = self.db.add_finding(self.run_id, "IDOR", "confirmed", "high",
                                  reproduction="GET /x -> token")
        r = self.disp.dispatch("record_attack_path", {
            "title": "ATO", "severity": "critical", "mitre": "T1190",
            "steps": [{"action": "exploit idor", "finding_id": fid,
                       "evidence": "token leaked"}]})
        self.assertFalse(r.is_error)
        self.assertIn("attack_path_id", r.content)
        self.assertEqual(len(self.db.attack_paths(self.run_id)), 1)

    def test_attack_path_warns_on_unconfirmed_finding(self):
        fid = self.db.add_finding(self.run_id, "maybe", "possible", "low")
        r = self.disp.dispatch("record_attack_path", {
            "title": "p", "steps": [{"action": "a", "finding_id": fid}]})
        self.assertFalse(r.is_error)        # recorded, but warned
        self.assertIn("warnings", r.content)

    def test_hypothesis_and_phase(self):
        r = self.disp.dispatch("record_hypothesis", {"statement": "maybe IDOR"})
        self.assertIn("hypothesis_id", r.content)
        r2 = self.disp.dispatch("set_phase", {"phase": "enumeration"})
        self.assertIn("enumeration", r2.content)
        self.assertEqual(self.db.get_run(self.run_id)["phase"], "enumeration")


# ---- full-loop test with the fake client ---------------------------------

class TestEngineLoop(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.db.init_schema()
        self.scope = _scope()
        self.reg = Registry.with_builtins()
        self.ex = SafeExecutor.from_limits(self.scope.limits)
        self.run_id = self.db.create_run("loop", "scope.yaml")

    def tearDown(self):
        self.db.close()

    def test_drives_tools_and_persists(self):
        # Script: set_phase -> (scope-blocked capability) -> record possible finding
        #         -> conclude.
        script = [
            _Response("tool_use", [_tool_use("t1", "set_phase",
                                             {"phase": "enumeration"})]),
            _Response("tool_use", [_tool_use("t2", "request_capability", {
                "capability": "network_discovery", "target": "10.10.10.10",
                "reason": "probe"})]),  # out of scope -> blocked, not executed
            _Response("tool_use", [_tool_use("t3", "record_finding", {
                "title": "Exposed service banner", "status": "possible",
                "severity": "low", "description": "banner reveals version"})]),
            _Response("tool_use", [_tool_use("t4", "conclude",
                                             {"summary": "Initial recon complete."})]),
        ]
        # Replace the client factory with our fake.
        engine_mod._anthropic_client = lambda: _FakeClient(script)

        events = []
        eng = engine_mod.ReasoningEngine(
            self.scope, self.reg, self.ex, self.db, self.run_id,
            max_safety=SafetyLevel.ACTIVE, model="fake", max_steps=10,
            on_event=events.append,
        )
        result = eng.run("127.0.0.1", "test objective")

        # A live progress event must have been emitted with a step budget.
        prog = [e for e in events if e.kind == "progress"]
        self.assertTrue(prog)
        self.assertEqual(prog[-1].detail["max_steps"], 10)
        self.assertIn("percent", prog[-1].detail)

        self.assertTrue(result.concluded)
        self.assertEqual(result.summary, "Initial recon complete.")
        self.assertEqual(result.capability_calls, 1)
        self.assertEqual(result.findings_recorded, 1)
        # The out-of-scope capability must be recorded as blocked (audit), not run.
        blocked = self.db.blocked_tests(self.run_id)
        self.assertEqual(len(blocked), 1)
        self.assertIn("SCOPE DENIED", blocked[0]["reason"])
        # Phase advanced to reporting and status to completed on conclude.
        self.assertEqual(self.db.get_run(self.run_id)["phase"], "reporting")
        self.assertEqual(self.db.get_run(self.run_id)["status"], "completed")
        # A finding exists.
        self.assertEqual(self.db.count("findings", self.run_id), 1)


class TestResume(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.db.init_schema()
        self.run_id = self.db.create_run("resume", "")

    def tearDown(self):
        self.db.close()

    def test_no_context_when_empty(self):
        self.assertIsNone(engine_mod.build_resume_context(self.db, self.run_id))

    def test_context_includes_prior_state(self):
        tid = self.db.record_test(self.run_id, "service_detection", "nmap",
                                  "10.0.0.1", ["nmap"], "ok", 0)
        self.db.add_observation(self.run_id, tid, "open_port", "10.0.0.1:80",
                                {"host": "10.0.0.1", "port": 80, "service": "http"})
        self.db.add_hypothesis(self.run_id, "possible IDOR on /api")
        self.db.add_finding(self.run_id, "Dir listing", "confirmed", "medium",
                            reproduction="GET /x -> 200")
        ctx = engine_mod.build_resume_context(self.db, self.run_id)
        self.assertIsNotNone(ctx)
        self.assertIn("RESUMING", ctx)
        self.assertIn("possible IDOR", ctx)
        self.assertIn("Dir listing", ctx)
        self.assertIn("10.0.0.1:80", ctx)


if __name__ == "__main__":
    unittest.main(verbosity=2)
