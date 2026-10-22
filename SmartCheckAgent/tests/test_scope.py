"""Tests for the deterministic scope gate — the security core.

Run: python -m pytest tests/ -q   (or: python tests/test_scope.py)
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from smartcheck.scope import Scope, ScopeError, parse_port_spec  # noqa: E402

SCOPE_YAML = """
authorization:
  authorized_by: tester
targets:
  ips: [127.0.0.1, "::1"]
  cidrs: [192.168.56.0/24, "2001:db8::/32"]
  domains: [target.lab, localhost]
  urls: ["http://10.0.0.5:8080/app"]
ports:
  allowed: [80, 443, 8080]
options:
  allow_subdomains: true
limits:
  requests_per_second: 7
  max_concurrency: 4
"""


def _load(text: str) -> Scope:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
        path = f.name
    return Scope.load(Path(path))


class TestScope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = _load(SCOPE_YAML)

    # --- allow cases ---
    def test_explicit_ip(self):
        self.assertTrue(self.scope.check("127.0.0.1").allowed)

    def test_ipv6_explicit(self):
        self.assertTrue(self.scope.check("::1").allowed)

    def test_cidr_member(self):
        self.assertTrue(self.scope.check("192.168.56.200").allowed)

    def test_ipv6_cidr_member(self):
        self.assertTrue(self.scope.check("2001:db8::dead").allowed)

    def test_explicit_domain(self):
        self.assertTrue(self.scope.check("target.lab").allowed)

    def test_subdomain_allowed(self):
        self.assertTrue(self.scope.check("api.target.lab").allowed)

    def test_url_host_from_urls_list(self):
        d = self.scope.check("http://10.0.0.5:8080/app")
        self.assertTrue(d.allowed)

    def test_url_port_auto_authorized(self):
        # 8080 came from the urls entry even though not in ports.allowed originally
        self.assertIn(8080, self.scope.allowed_ports)

    # --- deny cases (deny-by-default) ---
    def test_public_ip_denied(self):
        self.assertFalse(self.scope.check("8.8.8.8").allowed)

    def test_unlisted_host_denied(self):
        self.assertFalse(self.scope.check("evil.com").allowed)

    def test_cidr_neighbor_denied(self):
        self.assertFalse(self.scope.check("192.168.57.1").allowed)

    def test_bad_port_denied(self):
        self.assertFalse(self.scope.check("127.0.0.1", port=3306).allowed)

    def test_good_port_allowed(self):
        self.assertTrue(self.scope.check("127.0.0.1", port=443).allowed)

    def test_host_port_in_target_string(self):
        self.assertFalse(self.scope.check("127.0.0.1:3306").allowed)
        self.assertTrue(self.scope.check("127.0.0.1:80").allowed)

    def test_sibling_domain_not_subdomain(self):
        # nottarget.lab must NOT match target.lab
        self.assertFalse(self.scope.check("nottarget.lab").allowed)

    def test_empty_target_denied(self):
        self.assertFalse(self.scope.check("").allowed)

    # --- loader guards ---
    def test_missing_targets_raises(self):
        with self.assertRaises(ScopeError):
            _load("authorization: {authorized_by: x}\ntargets: {}\n")

    def test_invalid_ip_raises(self):
        with self.assertRaises(ScopeError):
            _load("targets:\n  ips: [999.1.1.1]\n")

    def test_limits_parsed(self):
        self.assertEqual(self.scope.limits.requests_per_second, 7)
        self.assertEqual(self.scope.limits.max_concurrency, 4)

    # --- default_target() ---
    def test_default_target_single_ip_ignores_localhost(self):
        s = _load("targets:\n  ips: [10.129.227.148]\n  domains: [localhost]\n")
        t, _ = s.default_target()
        self.assertEqual(t, "10.129.227.148")

    def test_default_target_cidr_is_ambiguous(self):
        s = _load("targets:\n  ips: [10.0.0.5]\n  cidrs: [10.0.0.0/24]\n")
        t, reason = s.default_target()
        self.assertIsNone(t)
        self.assertIn("CIDR", reason)

    def test_default_target_multiple_hosts_ambiguous(self):
        s = _load("targets:\n  ips: [10.0.0.5]\n  domains: [app.lab]\n")
        self.assertIsNone(s.default_target()[0])

    def test_default_target_single_url(self):
        s = _load("targets:\n  urls: [\"http://app.lab:8080/\"]\n")
        self.assertEqual(s.default_target()[0], "app.lab")

    # --- port spec parsing + check_ports ---
    def test_parse_port_spec_list_and_range(self):
        self.assertEqual(parse_port_spec("22,80,8000-8002"),
                         {22, 80, 8000, 8001, 8002})

    def test_parse_port_spec_oversized_range_raises(self):
        with self.assertRaises(ValueError):
            parse_port_spec("1-70000", cap=1000)

    def test_check_ports_empty_allows_all(self):
        s = _load("targets:\n  ips: [1.2.3.4]\n")  # no ports => all allowed
        self.assertEqual(s.check_ports({22, 3306}), (True, []))

    def test_check_ports_flags_out_of_scope(self):
        ok_, bad = self.scope.check_ports({80, 3306, 22})
        self.assertFalse(ok_)
        self.assertEqual(bad, [22, 3306])   # 80 allowed; 22/3306 not


if __name__ == "__main__":
    unittest.main(verbosity=2)
