"""Offline tests for paired CORS validation; never contact the internet."""
import unittest
from email.message import Message
from decrypto_validation import ORIGINS, evaluate_cors_pair, metadata


class TestPairedCors(unittest.TestCase):
    def samples(self, reflected=True):
        out = []
        for origin in ORIGINS:
            headers = Message()
            headers["Access-Control-Allow-Origin"] = origin if reflected else "https://trusted.example"
            headers["Access-Control-Allow-Credentials"] = "true"
            out.append(metadata(origin, 200, headers))
        return out

    def test_positive_control(self):
        result = evaluate_cors_pair("https://fixture.example/", self.samples())
        self.assertTrue(result["evidence"]["both_untrusted_origins_reflected_with_credentials"])
        self.assertIn("not demonstrated", result["status"])

    def test_negative_control(self):
        result = evaluate_cors_pair("https://fixture.example/", self.samples(reflected=False))
        self.assertFalse(result["evidence"]["both_untrusted_origins_reflected_with_credentials"])

    def test_incomplete_pair(self):
        result = evaluate_cors_pair("https://fixture.example/", self.samples()[:1])
        self.assertFalse(result["evidence"]["complete"])

    def test_no_arbitrary_header_leak(self):
        headers = Message()
        headers["Set-Cookie"] = "session=secret"
        sample = metadata(ORIGINS[0], 200, headers)
        self.assertNotIn("secret", str(sample))


if __name__ == "__main__":
    unittest.main()
