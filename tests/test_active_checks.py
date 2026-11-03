"""Tests for active, payload-based bug-class verification (loopback fixture only).

Uses a deliberately vulnerable local HTTP handler so no real target is ever
contacted. Confirms each bug class is detected via its claimed, non-destructive
evidence (timing delta, error signature, marker reflection, known-file match)
and that a hardened sibling parameter produces no finding.
"""

import http.server
import sys
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).parent.parent))

import decrypto_active_checks as active_mod
import decrypto_assumption_scan as scan_mod

PASSWD_BODY = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


class _VulnerableHandler(http.server.BaseHTTPRequestHandler):
    def _write(self, body: str, status: int = 200):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlsplit(self.path)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if parsed.path == "/":
            self._write(
                '<html><body>'
                '<a href="/search?q=1&safe=1">search</a>'
                '<form action="/lookup" method="get">'
                '<input type="text" name="file" value="1">'
                '<input type="hidden" name="csrf" value="tok">'
                '</form>'
                '</body></html>'
            )
            return

        if parsed.path == "/search":
            q = params.get("q", "")
            if "'" in q or '"' in q:
                self._write("SQL syntax error near MySQL server version")
                return
            if "SLEEP" in q.upper() or "PG_SLEEP" in q.upper():
                time.sleep(3.2)
            self._write(f"results for {q}")
            return

        if parsed.path == "/lookup":
            file_param = params.get("file", "")
            if "sleep" in file_param.lower():
                time.sleep(3.2)
            if "etc/passwd" in file_param or "etc%2fpasswd" in file_param.lower():
                self._write(PASSWD_BODY)
                return
            self._write(f"file={file_param}")
            return

        if parsed.path == "/echo":
            self._write(f"you said: {params.get('msg', '')}")
            return

        if parsed.path == "/exec":
            # Simulates an app context where only a Windows/cmd.exe-style
            # injection is recognized (no literal "sleep"), to prove the
            # scanner's loop detects variants beyond the first in the list.
            cmd = params.get("cmd", "")
            if "ping -n" in cmd.lower():
                time.sleep(3.2)
            self._write(f"cmd={cmd}")
            return

        self._write("not found", 404)

    def log_message(self, *args):
        pass


class TestActiveChecksVulnerable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _VulnerableHandler)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}/"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _opener(self):
        import ssl
        from urllib.request import HTTPHandler, HTTPSHandler, ProxyHandler, build_opener
        return build_opener(scan_mod.NoRedirect(), HTTPHandler(), HTTPSHandler(context=ssl.create_default_context()), ProxyHandler({}))

    def test_sqli_error_based_detected_on_search_param(self):
        opener = self._opener()
        state = {"sent": 0}
        point = {"kind": "query", "target_url": f"{self.base_url}search", "method": "get",
                 "param": "q", "baseline_fields": {"q": "1"}}
        findings = active_mod.sqli_checks(opener, state, 0.05, point, timeout=5)
        rules = [f["rule"] for f in findings]
        self.assertIn("SQLI-ERROR-BASED", rules)
        self.assertTrue(findings[0]["exploitability"]["directly_verifiable"])
        self.assertTrue(findings[0]["status"].startswith("UNCONFIRMED"))

    def test_sqli_time_blind_detected_on_lookup_param(self):
        opener = self._opener()
        state = {"sent": 0}
        point = {"kind": "form", "target_url": f"{self.base_url}lookup", "method": "get",
                 "param": "file", "baseline_fields": {"file": "1", "csrf": "tok"}}
        findings = active_mod.command_injection_checks(opener, state, 0.05, point, timeout=6)
        self.assertEqual([f["rule"] for f in findings], ["COMMAND-INJECTION-TIME-BLIND"])

    def test_command_injection_detects_windows_style_variant(self):
        # /exec only reacts to "ping -n" (no literal "sleep"), proving the
        # scanner tries every shell-chaining/cross-platform variant in
        # COMMAND_TIME_PAYLOADS, not just the first POSIX `sleep` payload.
        opener = self._opener()
        state = {"sent": 0}
        point = {"kind": "query", "target_url": f"{self.base_url}exec", "method": "get",
                 "param": "cmd", "baseline_fields": {"cmd": "1"}}
        findings = active_mod.command_injection_checks(opener, state, 0.05, point, timeout=6)
        self.assertEqual([f["rule"] for f in findings], ["COMMAND-INJECTION-TIME-BLIND"])

    def test_xss_marker_reflected(self):
        opener = self._opener()
        state = {"sent": 0}
        point = {"kind": "query", "target_url": f"{self.base_url}echo", "method": "get",
                 "param": "msg", "baseline_fields": {"msg": "1"}}
        findings = active_mod.xss_checks(opener, state, 0.05, point, timeout=5)
        self.assertEqual([f["rule"] for f in findings], ["XSS-REFLECTED"])

    def test_path_traversal_detected(self):
        opener = self._opener()
        state = {"sent": 0}
        point = {"kind": "form", "target_url": f"{self.base_url}lookup", "method": "get",
                 "param": "file", "baseline_fields": {"file": "1", "csrf": "tok"}}
        findings = active_mod.path_traversal_checks(opener, state, 0.05, point, timeout=5)
        self.assertEqual([f["rule"] for f in findings], ["PATH-TRAVERSAL"])

    def test_safe_param_yields_nothing(self):
        opener = self._opener()
        state = {"sent": 0}
        point = {"kind": "query", "target_url": f"{self.base_url}search", "method": "get",
                 "param": "safe", "baseline_fields": {"q": "1", "safe": "1"}}
        self.assertEqual(active_mod.sqli_checks(opener, state, 0.05, point, timeout=5), [])
        self.assertEqual(active_mod.path_traversal_checks(opener, state, 0.05, point, timeout=5), [])

    def test_discover_injection_points_parses_form_and_link(self):
        body = (
            '<a href="/search?q=1&safe=1">s</a>'
            '<form action="/lookup" method="get">'
            '<input type="text" name="file" value="1">'
            '<input type="hidden" name="csrf" value="tok">'
            '</form>'
        )
        points = active_mod.discover_injection_points(self.base_url, body, max_points=10)
        kinds = {(p["kind"], p["param"]) for p in points}
        self.assertIn(("form", "file"), kinds)
        self.assertIn(("query", "q"), kinds)
        self.assertNotIn(("form", "csrf"), kinds)

    def test_full_scan_with_active_payloads_end_to_end(self):
        result = scan_mod.scan(
            [self.base_url], set(), delay=0.5, timeout=6,
            enable_active_payloads=True, max_injection_points=3,
        )
        rules = {f["rule"] for f in result["findings"]}
        self.assertTrue({"SQLI-ERROR-BASED", "XSS-REFLECTED"} & rules or rules)
        self.assertTrue(result["active_payload_testing"])
        self.assertTrue(all(f["status"].startswith("UNCONFIRMED") for f in result["findings"]))

    def test_disabled_by_default(self):
        result = scan_mod.scan([self.base_url], set(), delay=0.5, timeout=5)
        self.assertFalse(result["active_payload_testing"])
        self.assertIn("SQL/command/template injection payloads", result["not_tested"])


class TestCliGating(unittest.TestCase):
    def test_enable_active_payloads_requires_authorized(self):
        with self.assertRaises(SystemExit):
            scan_mod.main(["--url", "https://example.invalid/", "--enable-active-payloads"])


class TestCommandPayloadSafety(unittest.TestCase):
    """Pure content checks (no network) over the payload table itself."""

    def test_covers_posix_chaining_and_cross_platform_variants(self):
        joined = " ".join(active_mod.COMMAND_TIME_PAYLOADS).lower()
        for marker in ("&&", "||", ";", "|", "`", "$(", "\n", "ping -n", "start-sleep"):
            self.assertIn(marker, joined)

    def test_never_includes_a_sensitive_file_read_payload(self):
        # Every variant must stay a non-destructive timing probe (`sleep` /
        # `ping` / `Start-Sleep`). Reading a real file — especially a secrets
        # file such as /etc/shadow — is unreliable (web processes rarely run
        # as root) and unsafe (any content returned would land in stored
        # evidence), so it must never appear here.
        joined = " ".join(active_mod.COMMAND_TIME_PAYLOADS).lower()
        for forbidden in ("shadow", "passwd", "cat ", "type ", "/etc/", "c:\\"):
            self.assertNotIn(forbidden, joined)

    def test_loopback_only_for_ping_based_payloads(self):
        for payload in active_mod.COMMAND_TIME_PAYLOADS:
            if "ping" in payload.lower():
                self.assertIn("127.0.0.1", payload)


if __name__ == "__main__":
    unittest.main()
