"""Tests for header, CORS, redirect, sensitive-path and subdomain helpers (loopback fixture only)."""

import http.server
import re
import socket
import sys
import threading
import time
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
            self.send_header("Location", re.sub(r"[\r\n]", "", self.path.split("=", 1)[1]))
            self.end_headers()
            return
        self.send_response(200)
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

    def test_domain_scope_flows_into_result_and_report(self):
        domain_scope = {
            "domain": "example.test",
            "candidates_found": 5,
            "excluded_by_pattern": ["internal.example.test"],
            "live_and_in_scope": 3,
            "selected": [self.url],
            "truncated_by_ceiling": False,
        }
        result = scan_mod.scan([self.url], set(), delay=0.5, timeout=3, check_redirects=True, domain_scope=domain_scope)
        self.assertEqual(result["domain_scope"], domain_scope)
        self.assertIn("A01:2025", result["findings_by_owasp_top10_2025"])
        report = scan_mod.markdown_report(result)
        self.assertIn("## Domain-wide subdomain scope", report)
        self.assertIn("`example.test`", report)
        self.assertIn("Excluded by `--exclude-subdomain` pattern:** internal.example.test", report)
        self.assertIn("## Findings by OWASP Top 10:2025 category", report)
        self.assertIn("has not published a separate 2026 edition", report)
        self.assertIn("**OWASP 2025:** A01:2025", report)

    def test_no_domain_scope_omits_domain_section(self):
        result = scan_mod.scan([self.url], set(), delay=0.5, timeout=3)
        self.assertIsNone(result["domain_scope"])
        self.assertNotIn("## Domain-wide subdomain scope", scan_mod.markdown_report(result))


class TestSecurityHeaders(unittest.TestCase):
    def test_hardened_response_has_no_findings(self):
        headers = Message()
        headers["X-Frame-Options"] = "DENY"
        headers["X-Content-Type-Options"] = "nosniff"
        headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'"
        headers["Referrer-Policy"] = "no-referrer"
        headers["Permissions-Policy"] = "camera=()"
        self.assertEqual(scan_mod.security_header_checks("https://x/", 200, headers), [])

    def test_error_status_skipped(self):
        self.assertEqual(scan_mod.security_header_checks("https://x/", 500, Message()), [])


class TestTls(unittest.TestCase):
    def test_expired_certificate_reported(self):
        exc = scan_mod.ssl.SSLCertVerificationError(1, "certificate has expired")
        exc.verify_message = "certificate has expired"
        with mock.patch.object(scan_mod.socket, "create_connection", side_effect=exc):
            findings = scan_mod.tls_checks("expired.test", 443, 1)
        self.assertEqual([f["rule"] for f in findings], ["TLS-CERT-EXPIRY"])

    def test_unreachable_host_yields_nothing(self):
        self.assertEqual(scan_mod.tls_checks("127.0.0.1", 1, 1), [])


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

    def test_discover_default_covers_every_live_subdomain(self):
        live = {"example.com": ["1.1.1.1"], "a.example.com": ["1.1.1.2"], "b.example.com": ["1.1.1.3"]}
        with mock.patch.object(sub_mod, "discover_subdomains_crtsh", return_value={"b.example.com", "a.example.com"}), \
                mock.patch.object(sub_mod, "resolve_live_hosts", return_value=live):
            urls = sub_mod.discover_authorized_subdomains("example.com")
        self.assertEqual(sorted(urls), ["https://a.example.com/", "https://b.example.com/", "https://example.com/"])

    def test_normalize_exclusions_lowercases_and_strips(self):
        self.assertEqual(
            sub_mod.normalize_exclusions([" Dev-A.Example.com ", "", None, "b.example.com."]),
            frozenset({"dev-a.example.com", "b.example.com"}),
        )
        self.assertEqual(sub_mod.normalize_exclusions(None), frozenset())

    def test_is_excluded_matches_exact_and_glob(self):
        patterns = sub_mod.normalize_exclusions(["internal.example.com", "dev-*.example.com"])
        self.assertTrue(sub_mod.is_excluded("internal.example.com", patterns))
        self.assertTrue(sub_mod.is_excluded("dev-staging.example.com", patterns))
        self.assertTrue(sub_mod.is_excluded("DEV-STAGING.example.com", patterns))
        self.assertFalse(sub_mod.is_excluded("a.example.com", patterns))

    def test_discover_excludes_matching_hostnames(self):
        live = {"example.com": ["1.1.1.1"], "a.example.com": ["1.1.1.2"], "dev-x.example.com": ["1.1.1.3"]}

        def resolve_only_requested(hostnames, **_kwargs):
            return {h: live[h] for h in hostnames if h in live}

        with mock.patch.object(sub_mod, "discover_subdomains_crtsh",
                                return_value={"a.example.com", "dev-x.example.com"}), \
                mock.patch.object(sub_mod, "resolve_live_hosts", side_effect=resolve_only_requested):
            urls = sub_mod.discover_authorized_subdomains("example.com", exclude=["dev-*.example.com"])
        self.assertEqual(sorted(urls), ["https://a.example.com/", "https://example.com/"])

    def test_report_includes_discovery_and_exclusion_metadata(self):
        live = {"example.com": ["1.1.1.1"], "a.example.com": ["1.1.1.2"]}

        def resolve_only_requested(hostnames, **_kwargs):
            return {h: live[h] for h in hostnames if h in live}

        with mock.patch.object(sub_mod, "discover_subdomains_crtsh",
                                return_value={"a.example.com", "dev-x.example.com"}), \
                mock.patch.object(sub_mod, "resolve_live_hosts", side_effect=resolve_only_requested):
            report = sub_mod.discover_authorized_subdomains_report(
                "example.com", exclude=["dev-*.example.com"], max_subdomains=1,
            )
        self.assertEqual(report["domain"], "example.com")
        self.assertEqual(report["candidates_found"], 3)  # a, dev-x, + apex
        self.assertEqual(report["excluded_by_pattern"], ["dev-x.example.com"])
        self.assertEqual(report["live_and_in_scope"], 2)
        self.assertEqual(report["selected"], ["https://example.com/"])
        self.assertTrue(report["truncated_by_ceiling"])

    def test_resolve_live_hosts_returns_sorted_unique_addresses(self):
        def fake_getaddrinfo(host, port):
            return [(2, 1, 6, "", ("1.1.1.2", 0)), (2, 1, 6, "", ("1.1.1.1", 0)), (2, 1, 6, "", ("1.1.1.1", 0))]

        with mock.patch.object(sub_mod.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
            live = sub_mod.resolve_live_hosts({"a.example.test"}, timeout=1, max_hosts=5)
        self.assertEqual(live, {"a.example.test": ["1.1.1.1", "1.1.1.2"]})

    def test_resolve_live_hosts_excludes_hosts_that_fail_to_resolve(self):
        with mock.patch.object(sub_mod.socket, "getaddrinfo", side_effect=socket.gaierror("not found")):
            live = sub_mod.resolve_live_hosts({"a.example.test"}, timeout=1, max_hosts=5)
        self.assertEqual(live, {})

    def test_resolve_live_hosts_respects_max_hosts_cap(self):
        calls = []

        def fake_getaddrinfo(host, port):
            calls.append(host)
            return [(2, 1, 6, "", ("1.1.1.1", 0))]

        hostnames = {f"h{i}.example.test" for i in range(10)}
        with mock.patch.object(sub_mod.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
            sub_mod.resolve_live_hosts(hostnames, timeout=1, max_hosts=3)
        self.assertEqual(len(calls), 3)

    def test_resolve_live_hosts_runs_concurrently_and_bounds_slow_lookups(self):
        """A hanging lookup must not block collection of the other, faster results."""
        def fake_getaddrinfo(host, port):
            if host == "slow.example.test":
                time.sleep(2)
            return [(2, 1, 6, "", ("203.0.113.1", 0))]

        hostnames = {"a.example.test", "b.example.test", "slow.example.test"}
        with mock.patch.object(sub_mod.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
            start = time.monotonic()
            live = sub_mod.resolve_live_hosts(hostnames, timeout=0.3, max_hosts=10, max_workers=10)
            elapsed = time.monotonic() - start
        self.assertEqual(set(live), {"a.example.test", "b.example.test"})
        self.assertLess(elapsed, 1.5, "slow lookup should be abandoned, not waited out serially")

    def test_max_subdomains_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            sub_mod.discover_authorized_subdomains("example.com", max_subdomains=0)
        with self.assertRaises(ValueError):
            sub_mod.discover_authorized_subdomains("example.com", max_subdomains=sub_mod.MAX_SUBDOMAINS_CEILING + 1)


if __name__ == "__main__":
    unittest.main()
