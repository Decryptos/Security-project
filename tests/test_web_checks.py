"""Tests for header, CORS, redirect, sensitive-path and subdomain helpers (loopback fixture only)."""

import http.server
import sys
import threading
import unittest
from email.message import Message
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

import decrypto_assumption_scan as scan_mod
import decrypto_subdomain_scan as sub_mod


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200 if self.path in ("/", "/.git/HEAD") else 404)
        self.send_header("Server", "nginx/1.18.0")
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/?redirect="):
            self.send_response(302)
            self.send_header("Location", self.path.split("=", 1)[1])
            self.end_headers()
            return
        origin = self.headers.get("Origin")
        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    def log_message(self, *args):
        pass


class TestLiveChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}/"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_full_scan_rules_and_exploitability(self):
        result = scan_mod.scan(
            [self.url], set(), delay=0.5, timeout=3,
            check_redirects=True, check_sensitive_paths=True,
        )
        by_rule = {f["rule"]: f for f in result["findings"]}
        for rule in ("OPEN-REDIRECT", "SENSITIVE-PATH-EXPOSED",
                     "SERVER-BANNER", "CLICKJACK-HEADERS", "MIME-SNIFF"):
            self.assertIn(rule, by_rule)
        self.assertTrue(by_rule["OPEN-REDIRECT"]["exploitability"]["directly_verifiable"])
        self.assertFalse(by_rule["SENSITIVE-PATH-EXPOSED"]["exploitability"]["directly_verifiable"])
        self.assertTrue(all(f["status"].startswith("UNCONFIRMED") for f in result["findings"]))
        self.assertIn("Exploitability verification", scan_mod.markdown_report(result))


class TestSecurityHeaders(unittest.TestCase):
    def test_hardened_response_has_no_findings(self):
        headers = Message()
        headers["X-Frame-Options"] = "DENY"
        headers["X-Content-Type-Options"] = "nosniff"
        self.assertEqual(scan_mod.security_header_checks("https://x/", 200, headers), [])

    def test_error_status_skipped(self):
        self.assertEqual(scan_mod.security_header_checks("https://x/", 500, Message()), [])


class TestSubdomains(unittest.TestCase):
    def test_crtsh_parsing_filters_out_of_scope_and_wildcards(self):
        payload = (b'[{"name_value": "a.example.com\\n*.b.example.com"},'
                   b'{"name_value": "evil.com\\nexample.com.evil.com"}]')
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = payload
        with mock.patch.object(sub_mod, "urlopen", return_value=response):
            names = sub_mod.discover_subdomains_crtsh("example.com")
        self.assertEqual(names, {"a.example.com", "b.example.com"})

    def test_invalid_domain_rejected(self):
        with self.assertRaises(ValueError):
            sub_mod.discover_subdomains_crtsh("bad domain/../")

    def test_discover_orders_apex_first_and_caps(self):
        live = {"example.com": ["1.1.1.1"], "a.example.com": ["1.1.1.2"], "b.example.com": ["1.1.1.3"]}
        with mock.patch.object(sub_mod, "discover_subdomains_crtsh", return_value={"b.example.com", "a.example.com"}), \
                mock.patch.object(sub_mod, "resolve_live_hosts", return_value=live):
            urls = sub_mod.discover_authorized_subdomains("example.com", max_subdomains=2)
        self.assertEqual(urls, ["https://example.com/", "https://a.example.com/"])


if __name__ == "__main__":
    unittest.main()
