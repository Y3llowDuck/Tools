"""Tests for plugin auto-onboarding: spec validation, the GeneratedPlugin
interpreter, generation via a mocked model, and registry loading.

No Anthropic API key or network is used — the model call is mocked.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="smartcheck-onboard-")
os.environ["SMARTCHECK_DATA_DIR"] = _TMP
os.environ["SMARTCHECK_DB"] = str(Path(_TMP) / "test.db")
os.environ["SMARTCHECK_PLUGINS_DIR"] = str(Path(_TMP) / "plugins")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from smartcheck import onboarding  # noqa: E402
from smartcheck.models import CapabilityRequest  # noqa: E402
from smartcheck.plugins.generated import (GeneratedPlugin, SpecError,  # noqa: E402
                                          validate_spec)
from smartcheck.plugins.registry import Registry  # noqa: E402

GOOD_SPEC = {
    "name": "ffuf", "binary": "ffuf", "capabilities": ["web_content_discovery"],
    "safety_level": "active", "execution_type": "one_shot",
    "argv": {"base": ["ffuf", "-json"],
             "target": {"mode": "flag", "flag": "-u"},
             "params": [{"name": "wordlist", "flag": "-w", "type": "path",
                         "required": True, "default_paths": ["/etc/hostname"]}]},
    "parser": {"type": "json_lines", "observation_kind": "discovered_path",
               "fields": {"url": "url", "status": "status"},
               "summary": "{status} {url}"},
}


class TestSpecValidation(unittest.TestCase):
    def test_good(self):
        self.assertEqual(validate_spec(GOOD_SPEC), [])

    def test_missing_keys(self):
        self.assertTrue(validate_spec({"name": "x"}))

    def test_bad_safety(self):
        s = dict(GOOD_SPEC); s = json.loads(json.dumps(s)); s["safety_level"] = "nope"
        self.assertTrue(any("safety_level" in e for e in validate_spec(s)))

    def test_bad_parser(self):
        s = json.loads(json.dumps(GOOD_SPEC)); s["parser"]["type"] = "weird"
        self.assertTrue(any("parser.type" in e for e in validate_spec(s)))

    def test_bad_regex(self):
        s = json.loads(json.dumps(GOOD_SPEC))
        s["parser"] = {"type": "regex", "pattern": "([a-z", "observation_kind": "m"}
        self.assertTrue(any("regex" in e for e in validate_spec(s)))

    def test_constructing_bad_spec_raises(self):
        with self.assertRaises(SpecError):
            GeneratedPlugin({"name": "x"})


class TestInterpreter(unittest.TestCase):
    def test_build_argv_flag_target_and_params(self):
        p = GeneratedPlugin(GOOD_SPEC)
        req = CapabilityRequest("web_content_discovery", "http://t/", {})
        argv = p.build_argv(req)
        self.assertEqual(argv[:4], ["ffuf", "-json", "-u", "http://t/"])
        self.assertIn("-w", argv)

    def test_positional_target_and_host_only(self):
        spec = json.loads(json.dumps(GOOD_SPEC))
        spec["argv"]["target"] = {"mode": "positional", "use_host_only": True}
        spec["argv"]["params"] = []
        p = GeneratedPlugin(spec)
        argv = p.build_argv(CapabilityRequest("web_content_discovery",
                                              "http://host:8080/x", {}))
        self.assertEqual(argv[-1], "host")  # scheme/port stripped

    def test_parse_json_lines(self):
        p = GeneratedPlugin(GOOD_SPEC)
        req = CapabilityRequest("web_content_discovery", "http://t/", {})
        obs = p.parse('{"url":"http://t/a","status":200}\nbad\n'
                      '{"url":"http://t/b","status":404}', "", req)
        self.assertEqual(len(obs), 2)
        self.assertEqual(obs[0].kind, "discovered_path")
        self.assertIn("200", obs[0].summary)

    def test_parse_json_record_path_and_filter(self):
        spec = json.loads(json.dumps(GOOD_SPEC))
        spec["parser"] = {"type": "json", "record_path": "results",
                          "observation_kind": "row",
                          "filter": {"key": "type", "equals": "hit"},
                          "fields": {"u": "url"}}
        p = GeneratedPlugin(spec)
        doc = '{"results":[{"type":"hit","url":"a"},{"type":"miss","url":"b"}]}'
        obs = p.parse(doc, "", CapabilityRequest("web_content_discovery", "t", {}))
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].data["u"], "a")

    def test_parse_regex(self):
        spec = json.loads(json.dumps(GOOD_SPEC))
        spec["parser"] = {"type": "regex",
                          "pattern": r"(?P<code>\d{3})\s+(?P<path>/\S+)",
                          "observation_kind": "hit", "summary": "{code} {path}"}
        p = GeneratedPlugin(spec)
        obs = p.parse("200 /admin\n404 /x", "",
                      CapabilityRequest("web_content_discovery", "t", {}))
        self.assertEqual(len(obs), 2)
        self.assertEqual(obs[0].data["code"], "200")


class TestExtractJson(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(onboarding._extract_json('{"a":1}'), {"a": 1})

    def test_fenced(self):
        self.assertEqual(onboarding._extract_json('```json\n{"a":1}\n```'), {"a": 1})

    def test_with_prose(self):
        self.assertEqual(onboarding._extract_json('Here:\n{"a": {"b": 2}}\ndone'),
                         {"a": {"b": 2}})


# ---- mocked model for generate_spec --------------------------------------

class _Block:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text):
        self.content = [_Block(text)]


class _FakeClient:
    def __init__(self, text):
        self._text = text
        self.messages = self

    def create(self, **kwargs):
        return _Resp(self._text)


class TestGenerateAndRegister(unittest.TestCase):
    def test_generate_valid_spec(self):
        payload = json.dumps(GOOD_SPEC)
        res = onboarding.generate_spec(
            "ffuf", "help text", "v1.0", ["web_content_discovery"],
            model="fake", client_factory=lambda: _FakeClient(payload))
        self.assertIsNotNone(res.spec)
        self.assertEqual(res.errors, [])
        self.assertEqual(res.spec["name"], "ffuf")

    def test_generate_bad_json(self):
        res = onboarding.generate_spec(
            "ffuf", "help", "", [], model="fake",
            client_factory=lambda: _FakeClient("sorry, no json here"))
        self.assertIsNone(res.spec)

    def test_save_and_registry_loads(self):
        onboarding.save_spec(GOOD_SPEC)
        reg = Registry.with_builtins()
        self.assertIsNotNone(reg.get("ffuf"))
        self.assertIn("ffuf", reg.capabilities()["web_content_discovery"])

    def test_generated_never_shadows_builtin(self):
        shadow = json.loads(json.dumps(GOOD_SPEC))
        shadow["name"] = "nmap"  # same as a built-in
        onboarding.save_spec(shadow)
        reg = Registry.with_builtins()
        # The built-in nmap must remain (NmapPlugin), not the generated one.
        self.assertEqual(type(reg.get("nmap")).__name__, "NmapPlugin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
