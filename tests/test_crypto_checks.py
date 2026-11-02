import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import decrypto_crypto_checks as checks


class TestCryptoChecks(unittest.TestCase):
    def scan(self, text):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "sample.py"
            path.write_text(text, encoding="utf-8")
            return checks._scan_text(path, root, text)

    def test_weak_hash_patterns_are_case_insensitive_and_include_sha1(self):
        findings = self.scan("MD5 sha1 SHA-1 Md4")
        hashes = [f for f in findings if f["rule"] == "CRYPTO-WEAK-HASH"]
        self.assertEqual(len(hashes), 4)

    def test_weak_cipher_patterns_are_case_insensitive(self):
        findings = self.scan("DES RC4 AES-ECB 3DES TripleDES")
        ciphers = [f for f in findings if f["rule"] == "CRYPTO-WEAK-CIPHER"]
        self.assertEqual(len(ciphers), 5)

    def test_repeated_matches_have_distinct_location_ids(self):
        findings = self.scan("MD5\nMD5\nMD5 and MD5")
        hashes = [f for f in findings if f["rule"] == "CRYPTO-WEAK-HASH"]
        self.assertEqual(len(hashes), 4)
        self.assertEqual(len({f["id"] for f in hashes}), 4)
        self.assertEqual(len({f["target"] for f in hashes}), 4)
        self.assertIn("sample.py:3:1", {f["target"] for f in hashes})
        self.assertIn("sample.py:3:9", {f["target"] for f in hashes})


if __name__ == "__main__":
    unittest.main()
