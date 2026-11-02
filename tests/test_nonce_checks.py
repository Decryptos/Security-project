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


if __name__ == "__main__":
    unittest.main()
