"""Tests for progress computation: step-budget blend + monotonicity."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="smartcheck-prog-")
os.environ["SMARTCHECK_DATA_DIR"] = _TMP
os.environ["SMARTCHECK_DB"] = str(Path(_TMP) / "test.db")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from smartcheck import progress  # noqa: E402
from smartcheck.db import Database  # noqa: E402


class TestProgress(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.db.init_schema()
        self.run_id = self.db.create_run("p", "")

    def tearDown(self):
        self.db.close()

    def test_step_budget_advances_within_phase(self):
        self.db.set_run_phase(self.run_id, "enumeration")
        low = progress.compute(self.db, self.run_id, step=2, max_steps=40).percent
        high = progress.compute(self.db, self.run_id, step=20, max_steps=40).percent
        self.assertGreater(high, low)          # bar moved with steps
        self.assertLessEqual(high, 85.0)       # capped below "almost done"

    def test_step_budget_capped(self):
        self.db.set_run_phase(self.run_id, "recon")
        pct = progress.compute(self.db, self.run_id, step=40, max_steps=40).percent
        self.assertLessEqual(pct, 85.0)

    def test_monotonic_no_regression(self):
        self.db.set_run_phase(self.run_id, "enumeration")
        hi = progress.compute(self.db, self.run_id, step=30, max_steps=40).percent
        # A later step-less recompute (e.g. `status`) must not drop it.
        after = progress.compute(self.db, self.run_id).percent
        self.assertGreaterEqual(after, hi)

    def test_reporting_reaches_full(self):
        self.db.set_run_phase(self.run_id, "reporting")
        pct = progress.compute(self.db, self.run_id, step=40, max_steps=40).percent
        self.assertEqual(pct, 100.0)

    def test_endpoint_coverage_advances_testing_phases(self):
        # With discovered endpoints but none tested, then some tested, the bar
        # must move — this is the real fix for the "stuck at 35%" plateau.
        self.db.set_run_phase(self.run_id, "exploitation")
        asset = self.db.add_asset(self.run_id, "host", "10.0.0.1")
        svc = self.db.add_service(self.run_id, asset, 80, "tcp", name="http")
        for i in range(4):
            self.db.add_endpoint(self.run_id, f"http://10.0.0.1/p{i}",
                                 service_id=svc, tested=0)
        low = progress.compute(self.db, self.run_id).percent
        self.db.add_endpoint(self.run_id, "http://10.0.0.1/p0", service_id=svc, tested=1)
        self.db.add_endpoint(self.run_id, "http://10.0.0.1/p1", service_id=svc, tested=1)
        high = progress.compute(self.db, self.run_id).percent
        self.assertGreater(high, low)

    def test_step_blend_bounded_by_current_phase(self):
        # Steps must not push the bar past the end of the current phase.
        self.db.set_run_phase(self.run_id, "enumeration")  # phases up to enum = 25%
        pct = progress.compute(self.db, self.run_id, step=39, max_steps=40).percent
        self.assertLessEqual(pct, 25.0)

    def test_bar_never_stalls_even_without_coverage(self):
        # THE run-6 failure mode: stuck in a work phase with zero endpoints ever
        # recorded (e.g. normalization produced nothing). The bar must still
        # advance on EVERY step — it must not depend on coverage to keep moving.
        for phase in ("recon", "enumeration", "vuln_analysis",
                      "exploitation", "post_validation"):
            self.db.set_run_phase(self.run_id, phase)
            prev = None
            for step in range(1, 41):
                pct = progress.compute(self.db, self.run_id,
                                       step=step, max_steps=40).percent
                if prev is not None:
                    self.assertGreater(
                        pct, prev,
                        f"progress bar stalled at {pct}% in {phase} at step {step}")
                prev = pct

    def test_steps_alone_never_reach_complete(self):
        # Effort alone (no coverage, not in reporting) must never show 100%.
        self.db.set_run_phase(self.run_id, "post_validation")
        pct = progress.compute(self.db, self.run_id, step=40, max_steps=40).percent
        self.assertLess(pct, 100.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
