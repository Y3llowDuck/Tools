"""Tests for the HTML report generator: structure, escaping, no leakage."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="smartcheck-report-")
os.environ["SMARTCHECK_DATA_DIR"] = _TMP
os.environ["SMARTCHECK_DB"] = str(Path(_TMP) / "test.db")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from smartcheck import report  # noqa: E402
from smartcheck.db import Database  # noqa: E402
from smartcheck.scope import Scope  # noqa: E402


def _authorized_scope() -> Scope:
    """A scope with real (non-placeholder) authorization, as a human would enter."""
    return Scope(ips={"10.0.0.1"},
                 authorization={"authorized_by": "Jane Tester",
                                "engagement": "Internal lab assessment #42",
                                "expires": "2026-12-31"})


class TestReport(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.db.init_schema()
        self.run_id = self.db.create_run("unit report", "")
        # Seed an observation and a finding, including a hostile string.
        tid = self.db.record_test(self.run_id, "service_detection", "nmap",
                                  "10.0.0.1", ["nmap"], "ok", 0)
        self.db.add_observation(self.run_id, tid, "open_port",
                                "10.0.0.1:80 open",
                                {"host": "10.0.0.1", "port": 80, "protocol": "tcp",
                                 "service": "http", "version": "nginx"})
        self.hid = self.db.add_hypothesis(self.run_id, "maybe IDOR", "evidence")
        self.db.add_finding(
            self.run_id,
            title="IDOR <script>alert(1)</script>",  # must be escaped
            status="confirmed", severity="high", cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N", cwe="CWE-639", owasp="API1:2023",
            description="Access to other users' objects.",
            reproduction="GET /api/user/2 -> 200 returns another user's data",
            remediation="Enforce per-object authorization.",
            hypothesis_id=self.hid,
        )

    def tearDown(self):
        self.db.close()

    def _render(self) -> str:
        out = Path(_TMP) / "r.html"
        report.generate(self.db, self.run_id, out, scope=_authorized_scope())
        return out.read_text()

    def test_refuses_without_manual_authorization(self):
        out = Path(_TMP) / "blocked.html"
        # No scope at all -> cannot verify authorization -> refuse.
        with self.assertRaises(report.UnauthorizedReportError):
            report.generate(self.db, self.run_id, out, scope=None)
        # Placeholder/blank authorization is treated as "not provided".
        for auth in ({},
                     {"authorized_by": "YOUR NAME / CLIENT CONTACT",
                      "engagement": "Describe the engagement / rules of engagement reference"},
                     {"authorized_by": "Real Person", "engagement": ""}):
            with self.assertRaises(report.UnauthorizedReportError):
                report.generate(self.db, self.run_id, out,
                                scope=Scope(authorization=auth))
        self.assertFalse(out.exists(), "report must not be written when refused")

    def test_renders_manual_authorization(self):
        h = self._render()
        self.assertIn("Jane Tester", h)
        self.assertIn("Internal lab assessment #42", h)

    def test_structure_and_finding(self):
        h = self._render()
        for anchor in ("id=\"exec\"", "id='surface'", "id=\"fsum\"",
                       "id='fdetail'", "id=\"stats\""):
            self.assertIn(anchor, h)
        self.assertIn("CWE-639", h)
        self.assertIn("API1:2023", h)
        self.assertIn("CONFIRMED", h)
        self.assertIn("10.0.0.1", h)

    def test_html_escaping_prevents_injection(self):
        h = self._render()
        # The raw script tag must NOT appear; its escaped form must.
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertIn("&lt;script&gt;", h)

    def test_well_formed(self):
        import html.parser

        class P(html.parser.HTMLParser):
            pass
        P().feed(self._render())  # raises on malformed structure

    def test_no_sensitive_leakage(self):
        h = self._render().lower()
        for bad in ("you are the reasoning core", "sk-ant", "anthropic",
                    "chain-of-thought", "system prompt"):
            self.assertNotIn(bad, h)


if __name__ == "__main__":
    unittest.main(verbosity=2)
