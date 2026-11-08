"""Authorized bounty scope, report export, and finding-identity controls.

Live checks use a loopback fixture only. No third-party bounty target is contacted.
"""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import decrypto_assumption_scan as scan_mod
from decrypto_assumption_scan import new_finding, sensitive_path_checks
from decrypto_bounty import asset_label, bounty_lead, load_scope


def _write_scope(directory, spec):
    path = Path(directory) / "scope.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


class TestScopeRules(unittest.TestCase):
    def scope(self, **overrides):
        spec = {
            "program": "Synthetic program",
            "in_scope": ["*.app.example.test", "https://api.example.test/v1/*", "127.0.0.1"],
            "out_of_scope": ["https://secret.app.example.test/", "https://api.example.test/v1/admin"],
        }
        spec.update(overrides)
        with tempfile.TemporaryDirectory() as tmp:
            return load_scope(_write_scope(tmp, spec))

    def test_wildcards_paths_and_excludes(self):
        scope = self.scope()
        self.assertTrue(scope.allows("https://a.app.example.test/health"))
        self.assertTrue(scope.allows("https://a.b.app.example.test/"))
        self.assertFalse(scope.allows("https://app.example.test/"))
        self.assertFalse(scope.allows("https://app.example.test.evil.test/"))
        self.assertFalse(scope.allows("https://secret.app.example.test/health"))
        self.assertTrue(scope.allows("https://api.example.test/v1/users"))
        self.assertTrue(scope.allows("https://api.example.test/v1/users?next=1"))
        self.assertFalse(scope.allows("https://api.example.test/v1/admin"))
        self.assertFalse(scope.allows("https://api.example.test/v2/users"))
        self.assertTrue(scope.allows("http://127.0.0.1:9/health"))
        self.assertFalse(scope.allows("https://out.example.test/"))
        self.assertFalse(scope.allows("https://user:secret@127.0.0.1/"))

    def test_asset_labels_and_rejections(self):
        scope = self.scope(code_assets=["local-fixture"])
        self.assertTrue(scope.allows_asset("127.0.0.1"))
        self.assertTrue(scope.allows_asset("local-fixture"))
        self.assertTrue(scope.allows_asset("https://api.example.test/v1/users"))
        self.assertFalse(scope.allows_asset("https://out.example.test/"))
        self.assertFalse(scope.allows_asset("../secrets"))
        with tempfile.TemporaryDirectory() as tmp:
            for spec in (
                {"program": "x", "in_scope": ["*"]},
                {"program": "x", "in_scope": ["https://*"]},
                {"program": "x", "in_scope": ["*.com"]},
                {"program": "x", "in_scope": ["http://user:secret@127.0.0.1/"]},
                {"program": "x", "in_scope": []},
                {"program": "x", "in_scope": ["127.0.0.1"], "unexpected": True},
            ):
                with self.assertRaises(ValueError):
                    load_scope(_write_scope(tmp, spec))

    def test_checked_in_scope_is_loopback_only(self):
        scope = load_scope(ROOT / "examples" / "bounty-scope.local.json")
        self.assertTrue(scope.allows("http://127.0.0.1:9/health"))
        self.assertTrue(scope.allows("http://localhost/"))
        self.assertTrue(scope.allows("http://[::1]/"))
        self.assertFalse(scope.allows("https://example.com/"))
        self.assertFalse(scope.allows("http://127.0.0.1/out-of-scope"))

    def test_scope_file_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text("{" + ("x" * 70000), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_scope(path)


class TestFindingIdentity(unittest.TestCase):
    def test_sensitive_paths_do_not_share_an_id(self):
        base = "http://127.0.0.1/"
        first = new_finding("SENSITIVE-PATH-EXPOSED", base, "t", "a", {"path": "/.env", "status": 200}, "r", "f", "v")
        second = new_finding("SENSITIVE-PATH-EXPOSED", base, "t", "a", {"path": "/.git/HEAD", "status": 200}, "r", "f", "v")
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(asset_label(first), "http://127.0.0.1/.env")
        self.assertEqual(asset_label(second), "http://127.0.0.1/.git/HEAD")
        self.assertTrue(first["status"].startswith("UNCONFIRMED"))

        def fake_send(opener, state, delay, url, method, origin, timeout):
            return 200, Message()

        with mock.patch.object(scan_mod, "_throttled_send", side_effect=fake_send):
            findings = sensitive_path_checks(None, {"sent": 0}, 0.5, base, 1)
        self.assertGreaterEqual(len(findings), 2)
        self.assertEqual(len({item["id"] for item in findings}), len(findings))

    def test_out_of_scope_probes_are_not_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = load_scope(_write_scope(tmp, {
                "program": "Loopback only",
                "in_scope": ["http://127.0.0.1:9/health"],
            }))
        calls = []

        def fake_send(opener, state, delay, url, method, origin, timeout):
            calls.append(url)
            return 200, Message()

        skipped = []
        with mock.patch.object(scan_mod, "_throttled_send", side_effect=fake_send):
            findings = sensitive_path_checks(
                None, {"sent": 0}, 0.5, "http://127.0.0.1:9/health", 1,
                allow=scope.allows, skipped=skipped,
            )
        self.assertEqual(findings, [])
        self.assertEqual(calls, [])
        self.assertTrue(any("/.git/HEAD" in item["url"] for item in skipped))

        with mock.patch.object(scan_mod, "send", side_effect=AssertionError("request sent")):
            with self.assertRaises(ValueError) as caught:
                scan_mod.scan(["http://127.0.0.1:9/admin"], set(), delay=0.5, timeout=1, scope=scope)
        self.assertIn("Out-of-scope", str(caught.exception))

    def test_discovered_hosts_outside_scope_are_not_contacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _write_scope(tmp, {
                "program": "Synthetic discovery scope",
                "in_scope": ["https://in.example.test/"],
            })
            out = Path(tmp) / "report"
            contacted = []

            def fake_send(opener, url, method, origin, timeout):
                contacted.append(url)
                if "out.example.test" in url:
                    raise AssertionError(url)
                return 200, Message()

            with mock.patch("decrypto_subdomain_scan.discover_authorized_subdomains",
                            return_value=["https://in.example.test/", "https://out.example.test/"]), \
                    mock.patch.object(scan_mod, "send", side_effect=fake_send), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = scan_mod.main([
                    "--scope", str(scope),
                    "--domain", "in.example.test",
                    "--authorized",
                    "--delay", "0.5",
                    "--timeout", "1",
                    "--out", str(out),
                ])
            self.assertEqual(code, 0)
            self.assertEqual(contacted, ["https://in.example.test/"])
            report = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
            skipped = {item["url"] for item in report["bounty"]["targets_skipped"]}
            self.assertIn("https://out.example.test/", skipped)

    def test_all_discovered_hosts_out_of_scope_contacts_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _write_scope(tmp, {
                "program": "Loopback only",
                "in_scope": ["127.0.0.1"],
            })
            with mock.patch("decrypto_subdomain_scan.discover_authorized_subdomains",
                            return_value=["https://out.example.test/"]), \
                    mock.patch.object(scan_mod, "send", side_effect=AssertionError("request sent")), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    scan_mod.main([
                        "--scope", str(scope),
                        "--domain", "out.example.test",
                        "--authorized",
                        "--delay", "0.5",
                        "--timeout", "1",
                        "--out", str(Path(tmp) / "report"),
                    ])
            self.assertEqual(caught.exception.code, 2)


class _Handler(BaseHTTPRequestHandler):
    seen = []

    def do_HEAD(self):
        self.seen.append(("HEAD", self.path))
        self.send_response(200)
        self.send_header("Set-Cookie", "sessionid=synthetic; Path=/")
        self.end_headers()

    def do_GET(self):
        self.seen.append(("GET", self.path))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


class TestBountyWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.origin = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)

    def setUp(self):
        _Handler.seen = []

    def test_cli_scope_draft_and_rejection(self):
        health = self.origin + "/health"
        admin = self.origin + "/admin"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = _write_scope(root, {
                "program": "Loopback fixture program",
                "in_scope": [health],
                "out_of_scope": [admin],
                "notes": "Local fixture only.",
            })
            refused = root / "refused"
            denied = subprocess.run(
                [sys.executable, str(ROOT / "decrypto_assumption_scan.py"),
                 "--scope", str(scope), "--url", admin, "--authorized",
                 "--delay", "0.5", "--out", str(refused)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(denied.returncode, 0, denied.stdout)
            self.assertIn("out-of-scope", denied.stderr.lower())
            self.assertEqual(_Handler.seen, [])
            self.assertFalse(refused.with_suffix(".json").exists())
            self.assertFalse(refused.with_suffix(".bounty.md").exists())

            prefix = root / "bounty_review"
            accepted = subprocess.run(
                [sys.executable, str(ROOT / "decrypto_assumption_scan.py"),
                 "--scope", str(scope), "--url", health, "--authorized",
                 "--check-sensitive-paths", "--delay", "0.5", "--out", str(prefix)],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn(("HEAD", "/health"), _Handler.seen)
            self.assertFalse(any(path.startswith("/.git") or path == "/.env" for _, path in _Handler.seen))
            report = json.loads(prefix.with_suffix(".json").read_text(encoding="utf-8"))
            draft = prefix.with_suffix(".bounty.md").read_text(encoding="utf-8")
            self.assertEqual(report["bounty"]["confirmed_vulnerability_count"], 0)
            self.assertGreaterEqual(len(report["bounty"]["targets_skipped"]), 2)
            self.assertTrue(report["bounty"]["leads"])
            identities = [lead["id"] for lead in report["bounty"]["leads"]]
            self.assertEqual(len(identities), len(set(identities)))
            self.assertIn("Loopback fixture program", draft)
            self.assertIn("Confirmed vulnerability:** no", draft)
            self.assertIn("CWE-", draft)
            self.assertIn("UNCONFIRMED", draft)
            self.assertNotIn("sessionid=synthetic", draft)
            self.assertNotIn("sessionid=synthetic", json.dumps(report))
            for lead in report["bounty"]["leads"]:
                self.assertFalse(lead["confirmed_vulnerability"])
                self.assertIn("Assumption, not confirmed impact", lead["assumption"])

    def test_static_export_redacts_literals_and_rejects_foreign_assets(self):
        secret = "abcdef0123456789abcdef0123456789abcdef99"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.py").write_text("A" * 40 + " = 1\nsecret = '%s'\n" % secret, encoding="utf-8")
            scope = _write_scope(root, {
                "program": "Local fixture",
                "in_scope": ["127.0.0.1"],
                "code_assets": ["local-fixture"],
            })
            out = root / "crypto_review"
            denied = subprocess.run(
                [sys.executable, str(ROOT / "decrypto_crypto_checks.py"),
                 "--scope", str(scope), "--asset", "https://out.example.test/",
                 "--out", str(out), str(root)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(denied.returncode, 0)
            self.assertFalse(out.with_suffix(".bounty.md").exists())
            accepted = subprocess.run(
                [sys.executable, str(ROOT / "decrypto_crypto_checks.py"),
                 "--scope", str(scope), "--asset", "local-fixture",
                 "--out", str(out), str(root)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            draft = out.with_suffix(".bounty.md").read_text(encoding="utf-8")
            packaged = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
            combined = accepted.stdout + draft + json.dumps(packaged)
            self.assertNotIn(secret, combined)
            self.assertIn("CWE-798", draft)
            self.assertIn("local-fixture", draft)
            hard = [item for item in packaged["findings"] if item["rule"] == "CRYPTO-HARDKEY"]
            self.assertEqual(len(hard), 1)
            self.assertEqual(hard[0]["evidence"]["line"], 2)

    def test_lead_redacts_secret_shaped_evidence(self):
        lead = bounty_lead({
            "id": "ABCDE12345",
            "rule": "CRYPTO-HARDKEY",
            "target": "sample.py:1:1",
            "title": "Possible hardcoded key or secret literal",
            "status": "UNCONFIRMED — needs owner validation",
            "priority": "review",
            "evidence_class": "static_code_finding",
            "taxonomy": {"category": "cryptographic-failures", "subtype": "hardcoded-key-or-secret", "cwe": "CWE-798", "owasp_top10_2021": "A02"},
            "evidence": {"file": "sample.py", "line": 1, "column": 1, "password": "super-secret", "source_sha256": "abc"},
            "remediation": "Remove it.",
            "validation_needed": "Confirm it is a real key.",
        }, program_asset="local-fixture")
        self.assertEqual(lead["evidence"]["password"], "redacted")
        self.assertNotIn("super-secret", json.dumps(lead))
        self.assertFalse(lead["confirmed_vulnerability"])


if __name__ == "__main__":
    unittest.main()
