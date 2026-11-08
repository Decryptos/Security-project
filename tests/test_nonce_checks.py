"""Offline regression controls for conservative AEAD nonce hypotheses."""
import tempfile
import unittest
from pathlib import Path

from decrypto_crypto_checks import scan_repo_for_crypto_issues


class TestAeadNonceChecks(unittest.TestCase):
    def _rules(self, code):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "sample.py").write_text(code, encoding="utf-8")
            result = scan_repo_for_crypto_issues(Path(tmp), ["python"])
            return [f["rule"] for f in result["findings"]], result

    def test_constant_nonce_detected_without_leaking_value(self):
        rules, result = self._rules(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "nonce = b'123456789012'\n"
            "aead.encrypt(nonce, plaintext, None)\n"
        )
        self.assertIn("CRYPTO-AEAD-STATIC-NONCE", rules)
        entry = next(f for f in result["findings"] if f["rule"] == "CRYPTO-AEAD-STATIC-NONCE")
        self.assertNotIn("123456789012", str(entry))

    def test_fixed_zero_nonce_detected(self):
        rules, _ = self._rules(
            "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n"
            "aead = ChaCha20Poly1305(key)\n"
            "aead.encrypt(b'\\\\x00' * 12, data, None)\n"
        )
        self.assertIn("CRYPTO-AEAD-STATIC-NONCE", rules)

    def test_random_nonce_not_flagged(self):
        rules, _ = self._rules(
            "import os\n"
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "nonce = os.urandom(12)\n"
            "aead.encrypt(nonce, data, None)\n"
        )
        self.assertNotIn("CRYPTO-AEAD-STATIC-NONCE", rules)

    def test_non_aead_encrypt_not_flagged(self):
        rules, _ = self._rules("cipher.encrypt(b'123456789012', data)\n")
        self.assertNotIn("CRYPTO-AEAD-STATIC-NONCE", rules)

    def _nonce_lines(self, code):
        _, result = self._rules(code)
        return [f["evidence"]["line"] for f in result["findings"] if f["rule"] == "CRYPTO-AEAD-STATIC-NONCE"]

    def test_parameter_and_rebinding_are_not_treated_as_fixed(self):
        lines = self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "nonce = b'123456789012'\n"
            "def run(aead, data, nonce):\n"
            "    aead.encrypt(nonce, data, None)\n"
            "aead.encrypt(nonce, data, None)\n"
        )
        self.assertEqual(lines, [6])

    def test_urandom_rebind_clears_the_constant(self):
        lines = self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "nonce = b'123456789012'\n"
            "nonce = os.urandom(12)\n"
            "aead.encrypt(nonce, data, None)\n"
        )
        self.assertEqual(lines, [])

    def test_functions_do_not_share_nonce_bindings(self):
        lines = self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "def bad(data):\n"
            "    nonce = b'123456789012'\n"
            "    aead.encrypt(nonce, data, None)\n"
            "def good(data):\n"
            "    nonce = os.urandom(12)\n"
            "    aead.encrypt(nonce, data, None)\n"
        )
        self.assertEqual(lines, [5])

    def test_instance_rebind_and_unrelated_import_are_not_aead(self):
        self.assertEqual(self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "aead = other\n"
            "aead.encrypt(b'123456789012', data, None)\n"
        ), [])
        self.assertEqual(self._nonce_lines(
            "from helpers import AESGCM\n"
            "aead = AESGCM(key)\n"
            "aead.encrypt(b'123456789012', data, None)\n"
        ), [])

    def test_branches_must_agree_and_comprehensions_shadow(self):
        self.assertEqual(self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "nonce = b'123456789012'\n"
            "if cond:\n"
            "    nonce = os.urandom(12)\n"
            "aead.encrypt(nonce, data, None)\n"
        ), [])
        self.assertEqual(self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "if cond:\n"
            "    nonce = b'123456789012'\n"
            "else:\n"
            "    nonce = b'123456789012'\n"
            "aead.encrypt(nonce, data, None)\n"
        ), [7])
        self.assertEqual(self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "if cond:\n"
            "    nonce = b'123456789012'\n"
            "    aead.encrypt(nonce, data, None)\n"
        ), [5])
        self.assertEqual(self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "nonce = b'123456789012'\n"
            "values = [aead.encrypt(nonce, data, None) for nonce in items]\n"
        ), [])

    def test_method_sees_module_instance_but_not_its_parameter(self):
        self.assertEqual(self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "class Box:\n"
            "    def enc(self, data):\n"
            "        aead.encrypt(b'123456789012', data, None)\n"
            "    def other(self, data, nonce):\n"
            "        aead.encrypt(nonce, data, None)\n"
        ), [5])

    def test_match_pattern_does_not_reuse_an_outer_constant(self):
        code = (
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "nonce = b'123456789012'\n"
            "match value:\n"
            "    case nonce:\n"
            "        aead.encrypt(nonce, data, None)\n"
        )
        try:
            compile(code, "<nonce>", "exec")
        except SyntaxError:
            self.skipTest("match statements require Python 3.10+")
        self.assertEqual(self._nonce_lines(code), [])

    def test_keyword_and_fromhex_nonces_are_fixed(self):
        self.assertEqual(self._nonce_lines(
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "aead = AESGCM(key)\n"
            "aead.encrypt(data, None, nonce=b'123456789012')\n"
            "aead.encrypt(bytes.fromhex('00112233445566778899aabb'), data, None)\n"
        ), [3, 4])


if __name__ == "__main__":
    unittest.main()
