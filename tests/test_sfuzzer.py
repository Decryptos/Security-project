"""Synthetic tests for authorized DNS wordlist discovery; no DNS is sent."""
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import decrypto_sfuzzer as sfuzzer
from decrypto_bounty import load_scope


class TestDecryptoSfuzzer(unittest.TestCase):
    def _scope(self, spec):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "scope.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        return load_scope(path)

    def _wildcard_scope(self, excludes=None):
        return self._scope({
            "program": "Synthetic DNS fixture",
            "in_scope": ["*.example.test"],
            "out_of_scope": excludes or [],
        })

    def test_domain_requires_apex_not_url_or_ip(self):
        self.assertEqual(sfuzzer.normalize_domain("Example.Test."), "example.test")
        for value in ("https://example.test", "127.0.0.1", "example.test/path", "bad..test"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sfuzzer.normalize_domain(value)

    def test_wordlist_accepts_dns_labels_not_http_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "labels.txt"
            path.write_text(
                "www\nadmin\nrobots.txt\nindex.php\n../private\n# comment\n",
                encoding="utf-8",
            )
            words, invalid = sfuzzer.load_wordlist(path, 10)
        self.assertEqual(words, ["www", "admin"])
        self.assertEqual(invalid, 3)

    def test_resolved_in_scope_name_records_families_not_addresses(self):
        scope = self._wildcard_scope()
        lookup = mock.Mock(return_value=["IPv4", "IPv6"])
        sleeper = mock.Mock()
        result = sfuzzer.enumerate_subdomains(
            "example.test", ["www"], scope, delay=0.5,
            resolver=lookup, sleeper=sleeper,
        )
        self.assertEqual(result["lookups_attempted"], 1)
        self.assertEqual(result["resolved"], [{
            "host": "www.example.test",
            "address_families": ["IPv4", "IPv6"],
        }])
        self.assertNotIn('"address":', json.dumps(result))
        lookup.assert_called_once_with("www.example.test")
        sleeper.assert_not_called()

    def test_out_of_scope_candidate_is_never_resolved(self):
        scope = self._wildcard_scope(["https://admin.example.test/"])
        lookup = mock.Mock(return_value=["IPv4"])
        result = sfuzzer.enumerate_subdomains(
            "example.test", ["admin", "www"], scope,
            delay=0.5, resolver=lookup, sleeper=mock.Mock(),
        )
        self.assertEqual(result["out_of_scope_skipped_count"], 1)
        self.assertEqual(result["lookups_attempted"], 1)
        lookup.assert_called_once_with("www.example.test")

    def test_nonexistent_names_are_not_reported_as_errors(self):
        scope = self._wildcard_scope()
        lookup = mock.Mock(side_effect=socket.gaierror(socket.EAI_NONAME, "synthetic"))
        result = sfuzzer.enumerate_subdomains(
            "example.test", ["missing"], scope, resolver=lookup,
            sleeper=mock.Mock(),
        )
        self.assertEqual(result["not_resolved_count"], 1)
        self.assertEqual(result["errors"], [])

    def test_transient_resolver_failure_is_redacted(self):
        scope = self._wildcard_scope()
        lookup = mock.Mock(side_effect=socket.gaierror(socket.EAI_AGAIN, "private resolver detail"))
        result = sfuzzer.enumerate_subdomains(
            "example.test", ["temporary"], scope, resolver=lookup,
            sleeper=mock.Mock(),
        )
        self.assertEqual(result["errors"], [{
            "host": "temporary.example.test",
            "error_type": "gaierror",
            "error_code": socket.EAI_AGAIN,
        }])
        self.assertNotIn("private resolver detail", json.dumps(result))

    def test_candidate_limit_fails_before_any_lookup(self):
        scope = self._wildcard_scope()
        lookup = mock.Mock(side_effect=AssertionError("lookup must not run"))
        with self.assertRaises(ValueError):
            sfuzzer.enumerate_subdomains(
                "example.test", ["www", "api"], scope, max_candidates=1,
                resolver=lookup,
            )
        lookup.assert_not_called()

    def test_scope_exclusion_prevents_all_dns_lookups_for_candidate(self):
        scope = self._wildcard_scope(["*.example.test"])
        lookup = mock.Mock(side_effect=AssertionError("out-of-scope DNS query"))
        result = sfuzzer.enumerate_subdomains(
            "example.test", ["admin"], scope, resolver=lookup,
            sleeper=mock.Mock(),
        )
        self.assertEqual(result["lookups_attempted"], 0)
        self.assertEqual(result["out_of_scope_skipped_count"], 1)
        lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
