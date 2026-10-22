"""Tests for observation -> knowledge-table normalization.

Verifies that parsed observations populate assets/services/endpoints/parameters,
that discovery vs. active testing set the `tested` flag correctly (so progress
coverage has real numbers), and that normalization is idempotent and
non-clobbering.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="smartcheck-norm-")
os.environ["SMARTCHECK_DATA_DIR"] = _TMP
os.environ["SMARTCHECK_DB"] = str(Path(_TMP) / "test.db")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from smartcheck.db import Database  # noqa: E402
from smartcheck.models import CapabilityRequest, Observation  # noqa: E402
from smartcheck.normalize import normalize  # noqa: E402


def _req(capability, target, run_id):
    return CapabilityRequest(capability=capability, target=target, run_id=run_id)


class TestNormalize(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.db.init_schema()
        self.run_id = self.db.create_run("n", "")

    def tearDown(self):
        self.db.close()

    def test_open_port_creates_asset_and_service(self):
        obs = [Observation(kind="open_port",
                           data={"host": "10.0.0.5", "port": 80, "protocol": "tcp",
                                 "service": "http", "version": "nginx 1.18"})]
        normalize(self.db, self.run_id, _req("service_detection", "10.0.0.5",
                                             self.run_id), obs)
        self.assertEqual(self.db.count("assets", self.run_id), 1)
        self.assertEqual(self.db.count("services", self.run_id), 1)

    def test_discovery_then_request_sets_tested(self):
        # feroxbuster discovers a path (not tested yet).
        normalize(self.db, self.run_id,
                  _req("web_content_discovery", "http://10.0.0.5/", self.run_id),
                  [Observation(kind="discovered_path",
                               data={"url": "http://10.0.0.5/admin", "status": 200,
                                     "content_length": 120, "method": "GET"})])
        self.assertEqual(self.db.count("endpoints", self.run_id), 1)
        self.assertEqual(self.db.count("endpoints", self.run_id, "tested=1"), 0)

        # curl actively requests that same URL -> becomes tested, no duplicate.
        normalize(self.db, self.run_id,
                  _req("http_request", "http://10.0.0.5/admin", self.run_id),
                  [Observation(kind="http_response",
                               data={"url": "http://10.0.0.5/admin", "method": "GET",
                                     "status_code": 200, "content_type": "text/html",
                                     "content_length": 120})])
        self.assertEqual(self.db.count("endpoints", self.run_id), 1)  # upsert, not dup
        self.assertEqual(self.db.count("endpoints", self.run_id, "tested=1"), 1)

    def test_query_parameters_extracted(self):
        normalize(self.db, self.run_id,
                  _req("http_request", "http://10.0.0.5/item?id=1&q=x", self.run_id),
                  [Observation(kind="http_response",
                               data={"url": "http://10.0.0.5/item?id=1&q=x",
                                     "method": "GET", "status_code": 200})])
        self.assertEqual(self.db.count("parameters", self.run_id), 2)
        # Idempotent: re-running does not add duplicate parameters.
        normalize(self.db, self.run_id,
                  _req("http_request", "http://10.0.0.5/item?id=1&q=x", self.run_id),
                  [Observation(kind="http_response",
                               data={"url": "http://10.0.0.5/item?id=1&q=x",
                                     "method": "GET", "status_code": 200})])
        self.assertEqual(self.db.count("parameters", self.run_id), 2)

    def test_endpoint_probe_does_not_clobber_nmap_service(self):
        # nmap records a rich service...
        normalize(self.db, self.run_id,
                  _req("service_detection", "10.0.0.5", self.run_id),
                  [Observation(kind="open_port",
                               data={"host": "10.0.0.5", "port": 80, "protocol": "tcp",
                                     "service": "http", "version": "nginx 1.18"})])
        # ...then an endpoint on the same host/port is normalized (knows only scheme).
        normalize(self.db, self.run_id,
                  _req("http_request", "http://10.0.0.5/", self.run_id),
                  [Observation(kind="http_response",
                               data={"url": "http://10.0.0.5/", "method": "GET",
                                     "status_code": 200})])
        self.assertEqual(self.db.count("services", self.run_id), 1)
        row = self.db._conn.execute(
            "SELECT version FROM services WHERE run_id=?", (self.run_id,)).fetchone()
        self.assertEqual(row["version"], "nginx 1.18")  # not blanked out

    def test_empty_scan_still_records_target_asset(self):
        normalize(self.db, self.run_id,
                  _req("http_request", "http://10.0.0.9/", self.run_id),
                  [Observation(kind="scan_complete", data={"url": "http://10.0.0.9/"})])
        self.assertEqual(self.db.count("assets", self.run_id), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
