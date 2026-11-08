"""Regressions for independent review findings; no external targets contacted."""
import json
import ssl
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest import mock

from decrypto_assumption_scan import security_header_checks, tls_checks, markdown_report, scan
from decrypto_bounty import load_scope, render_bounty_markdown
from decrypto_nonce_checks import check_python_aead_nonces


def rules(headers, status=200):
    return {entry["rule"]: entry for entry in security_header_checks("https://example.test/", status, headers)}


class ReviewRegressions(unittest.TestCase):
    def test_redirect_has_no_response_header_hardening_findings(self):
        self.assertEqual(rules(Message(), 301), {})

    def test_object_src_default_fallback(self):
        headers = Message()
        headers["Content-Security-Policy"] = "default-src 'none'; base-uri 'none'"
        self.assertNotIn("CSP-MISSING-DIRECTIVES", rules(headers))

    def test_multiple_csp_headers_intersect(self):
        headers = Message()
        headers["Content-Security-Policy"] = "default-src 'none'; base-uri 'none'"
        headers["Content-Security-Policy"] = "script-src * 'unsafe-inline'; base-uri *"
        results = rules(headers)
        self.assertNotIn("CSP-UNSAFE-INLINE", results)
        self.assertNotIn("CSP-WILDCARD-SOURCE", results)
        self.assertNotIn("CSP-MISSING-DIRECTIVES", results)

    def test_server_banner_cannot_break_json_fence(self):
        headers = Message()
        headers["Server"] = "Example/1.2.3" + chr(96) * 3 + "\n"
        finding = rules(headers)["SERVER-BANNER"]
        self.assertNotIn(chr(96), finding["evidence"]["banner_excerpt"])
        self.assertNotIn("\n", finding["evidence"]["banner_excerpt"])
        result = {
            "date_utc": "2026-11-08T00:00:00Z", "scope": ["https://example.test/"],
            "total_requests": 1, "finding_count": 1, "findings": [finding],
            "correlated_assumption_hypotheses": [],
        }
        self.assertNotIn("Example/1.2.3" + chr(96) * 3, markdown_report(result))

    def test_excluded_paths_ignore_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps({
                "program": "Fixture", "in_scope": ["https://example.test/"],
                "out_of_scope": ["https://example.test/admin/*"],
            }))
            scope = load_scope(path)
            self.assertFalse(scope.allows("https://example.test/Admin/x"))
            self.assertTrue(scope.allows("https://example.test/public"))

    def test_host_only_entry_covers_all_ports_by_design(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps({"program": "Fixture", "in_scope": ["example.test"]}))
            scope = load_scope(path)
            self.assertTrue(scope.allows("https://example.test:8443/"))
            self.assertTrue(scope.allows("http://example.test/"))

    def test_empty_bounty_lists_have_none(self):
        report = render_bounty_markdown({"bounty": {
            "program": "Fixture", "in_scope": [], "out_of_scope": [],
            "targets_requested": [], "leads": [], "confirmed_vulnerability_count": 0,
        }})
        for label in ("In-scope rules", "Out-of-scope rules", "Assets requested"):
            self.assertIn("**" + label + ":** (none)", report)

    def test_tls_verification_error_is_not_silent(self):
        error = ssl.SSLCertVerificationError(1, "certificate verify failed")
        error.verify_code = 10
        error.verify_message = "certificate has expired"
        with mock.patch("decrypto_assumption_scan.socket.create_connection", side_effect=error):
            entries = tls_checks("example.test", 443, 1)
        self.assertEqual([entry["rule"] for entry in entries], ["TLS-CERT-VERIFY"])
        self.assertEqual(entries[0]["evidence"]["verify_code"], 10)

    def test_all_checks_domain_url_cap_with_mocked_transport(self):
        # The 8-URL paired-CORS limit must not reject a 9-URL domain run.
        urls = ["https://%d.example.test/" % i for i in range(9)]
        with mock.patch("decrypto_assumption_scan.send", return_value=(200, Message())), \
             mock.patch("decrypto_assumption_scan.time.sleep"):
            result = scan(urls, set(), verify_cors=True, delay=0.5, max_urls=15)
        self.assertEqual(len(result["scope"]), 9)
        self.assertEqual(result["total_requests"], 27)

    def test_direct_constructor_encrypt_is_detected(self):
        source = ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                  "AESGCM(key).encrypt(b'\\\\x00'*12, data, None)\n")
        self.assertEqual(len(check_python_aead_nonces(source, "fixture.py")), 1)

    def test_fixed_nonce_in_exception_handler_is_detected(self):
        source = ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                  "aead = AESGCM(key)\n"
                  "try:\n    operation()\n"
                  "except ValueError:\n"
                  "    nonce = b'123456789012'\n"
                  "    aead.encrypt(nonce, data, None)\n")
        self.assertEqual(len(check_python_aead_nonces(source, "fixture.py")), 1)


if __name__ == "__main__":
    unittest.main()
