"""Tests for bug-class taxonomy and variant checks."""

import sys
import tempfile
import unittest
from email.message import Message
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import decrypto_assumption_scan as scan_mod
from decrypto_crypto_checks import scan_repo_for_crypto_issues
from decrypto_taxonomy import TAXONOMY, classify, summarize


def _headers(**values):
    msg = Message()
    for key, value in values.items():
        msg[key.replace("_", "-")] = value
    return msg


class TestTaxonomy(unittest.TestCase):
    def test_numeric_suffix_and_unknown(self):
        self.assertEqual(classify("SESSION-COOKIE-3")["category"], "session-management")
        self.assertEqual(classify("NOPE-RULE")["category"], "uncategorized")

    def test_every_emitted_rule_is_classified(self):
        for rule in ("TLS-HSTS", "OPEN-REDIRECT", "CSP-UNSAFE-INLINE", "CORS-WILDCARD", "CRYPTO-AEAD-STATIC-NONCE"):
            self.assertIn(rule, TAXONOMY)

    def test_summarize_groups_by_category_and_subtype(self):
        findings = [scan_mod.new_finding("OPEN-REDIRECT", "u", "t", "a", {}, "r", "f", "v")] * 2
        self.assertEqual(summarize(findings), {"redirect": {"unvalidated-redirect-parameter": 2}})


class TestHeaderVariants(unittest.TestCase):
    def rules(self, headers):
        return {f["rule"] for f in scan_mod.header_variant_checks("https://x/", 200, headers)}

    def test_weak_csp_variants(self):
        csp = "script-src * 'unsafe-inline' 'unsafe-eval'"
        rules = self.rules(_headers(Content_Security_Policy=csp))
        self.assertTrue({"CSP-UNSAFE-INLINE", "CSP-UNSAFE-EVAL", "CSP-WILDCARD-SOURCE", "CSP-MISSING-DIRECTIVES"} <= rules)
        self.assertNotIn("CSP-MISSING", rules)

    def test_missing_csp_and_policies(self):
        rules = self.rules(_headers())
        self.assertTrue({"CSP-MISSING", "REFERRER-POLICY", "PERMISSIONS-POLICY"} <= rules)

    def test_strong_headers_are_clean(self):
        headers = _headers(
            Content_Security_Policy="default-src 'self'; object-src 'none'; base-uri 'self'",
            Referrer_Policy="no-referrer", Permissions_Policy="camera=()",
        )
        self.assertEqual(self.rules(headers), set())

    def test_framework_banner_and_cors_wildcard(self):
        rules = self.rules(_headers(X_AspNet_Version="4.0.30319", Access_Control_Allow_Origin="*"))
        self.assertTrue({"FRAMEWORK-BANNER", "CORS-WILDCARD"} <= rules)


class TestStaticVariants(unittest.TestCase):
    def test_crypto_variants_detected(self):
        code = (
            "cipher = AES.new(key, AES.MODE_ECB)\n"
            "ctx.protocol = ssl.PROTOCOL_TLSv1\n"
            "ctx.check_hostname = False\n"
            "rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
            "pbkdf2_hmac('sha256', pw, salt, iterations=1000)\n"
            'jwt.decode(t, algorithms=["none"])\n'
            'iv = b"0123456789abcdef"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.py").write_text(code, encoding="utf-8")
            result = scan_repo_for_crypto_issues(Path(tmp))
        rules = {f["rule"] for f in result["findings"]}
        for rule in ("CRYPTO-ECB-MODE", "CRYPTO-TLS-OLD-PROTOCOL", "CRYPTO-TLS-WORKAROUND", "CRYPTO-SMALL-RSA-KEY",
                     "CRYPTO-WEAK-KDF-ITERATIONS", "CRYPTO-JWT-NONE-ALG", "CRYPTO-STATIC-IV"):
            self.assertIn(rule, rules)
        self.assertTrue(all("taxonomy" in f for f in result["findings"]))
        self.assertIn("cryptographic-failures", result["findings_by_category"])

    def test_secure_code_not_flagged_for_new_rules(self):
        code = "pbkdf2_hmac('sha256', pw, salt, iterations=600000)\nkey_size=3072\n"
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.py").write_text(code, encoding="utf-8")
            rules = {f["rule"] for f in scan_repo_for_crypto_issues(Path(tmp))["findings"]}
        self.assertNotIn("CRYPTO-WEAK-KDF-ITERATIONS", rules)
        self.assertNotIn("CRYPTO-SMALL-RSA-KEY", rules)


if __name__ == "__main__":
    unittest.main()
