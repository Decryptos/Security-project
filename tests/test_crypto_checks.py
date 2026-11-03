"""Unit tests for decrypto_crypto_checks module."""

import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path so we can import the modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from decrypto_crypto_checks import scan_repo_for_crypto_issues
import decrypto_crypto_checks as checks


def test_scan_detects_hardcoded_key():
    """Test that hardcoded keys are detected."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "vuln.py"
        p.write_text("secret = 'abcdef0123456789abcdef0123456789abcdef012345'\n")
        res = scan_repo_for_crypto_issues(Path(d), ["python"])
        assert res["meta"]["files_inspected"] == 1
        assert res["meta"]["finding_count"] >= 1


def test_scan_ignores_non_source_files():
    """Test that non-source files are ignored."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "binary.bin"
        p.write_bytes(b"\x00\x01\x02")
        res = scan_repo_for_crypto_issues(Path(d))
        assert res["meta"]["files_inspected"] == 0


def test_scan_empty_directory():
    """Test scanning an empty directory."""
    with tempfile.TemporaryDirectory() as d:
        res = scan_repo_for_crypto_issues(Path(d))
        assert len(res["findings"]) == 0
        assert res["meta"]["files_inspected"] == 0


def test_scan_detects_weak_hash():
    """Test that weak hash patterns are detected."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "weak.py"
        p.write_text("import hashlib\nh = hashlib.md5(b'data')")
        res = scan_repo_for_crypto_issues(Path(d))
        assert any(f["rule"] == "CRYPTO-WEAK-HASH" for f in res["findings"])



class TestCryptoCheckMatching(unittest.TestCase):
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


def load_tests(loader, tests, pattern):
    """Include standalone function controls in the stdlib CI test suite."""
    import unittest
    tests.addTests(unittest.FunctionTestCase(value) for name, value in globals().items()
                   if name.startswith("test_") and callable(value))
    return tests
