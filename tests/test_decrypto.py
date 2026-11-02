import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent.joinpath("decrypto_assumption_scan.py")
SPEC = importlib.util.spec_from_file_location("decrypto_assumption_scan", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TestDecryptoScanner(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(MODULE.normalize_url("https://example.com:443/"), "https://example.com/")
        self.assertEqual(MODULE.normalize_url("http://localhost:80/"), "http://localhost/")

    def test_has_auth_indicators(self):
        headers = MODULE.Message()
        headers.add_header("WWW-Authenticate", "Bearer realm=\"dev\"")
        self.assertTrue(MODULE.has_auth_indicators(headers))

    def test_no_auth_indicators_no_private_boundary(self):
        headers = MODULE.Message()
        headers.add_header("Cache-Control", "public,max-age=30")
        self.assertFalse(MODULE.has_auth_indicators(headers))


if __name__ == "__main__":
    unittest.main()
