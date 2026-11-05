"""Offline regression checks for static evidence privacy and scan coverage."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import decrypto_crypto_checks as checks


class TestStaticReporting(unittest.TestCase):
    def test_source_literals_are_never_copied_into_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = "password = 'p@ss!42'; digest = 'md5'\nnonce = b'a!b@c#d$e%f^'\n"
            (root / 'sample.py').write_text(source)
            result = checks.scan_repo_for_crypto_issues(root)
            rendered = json.dumps(result)
            self.assertNotIn('p@ss!42', rendered)
            self.assertNotIn('a!b@c#d$e%f^', rendered)
            self.assertTrue(result['findings'])
            for finding in result['findings']:
                self.assertNotIn('match_excerpt', finding['evidence'])
                self.assertEqual(finding['evidence']['source_sha256'],
                                 hashlib.sha256(source.encode()).hexdigest())

    def test_nonce_findings_have_stable_distinct_ids_and_taxonomy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'sample.py').write_text(
                'from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n'
                'aead = AESGCM(key)\n'
                "aead.encrypt(b'123456789012', data, None); aead.encrypt(b'123456789012', data, None)\n")
            first = checks.scan_repo_for_crypto_issues(root)
            second = checks.scan_repo_for_crypto_issues(root)
            entries = [f for f in first['findings'] if f['rule'] == 'CRYPTO-AEAD-STATIC-NONCE']
            self.assertEqual(len(entries), 2)
            self.assertEqual(len({f['id'] for f in entries}), 2)
            self.assertEqual(first, second)
            for entry in entries:
                self.assertIn('taxonomy', entry)
                self.assertIn('source_sha256', entry['evidence'])
                self.assertIn('validation_needed', entry)

    def test_skipped_source_files_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'large.py').write_bytes(b' ' * 1_048_577)
            (root / 'invalid.py').write_bytes(b'\xff')
            (root / 'ok.py').write_text('value = 1\n')
            result = checks.scan_repo_for_crypto_issues(root)
            self.assertEqual(result['meta']['files_inspected'], 1)
            self.assertEqual({s['file'] for s in result['meta']['skipped']},
                             {'large.py', 'invalid.py'})

    def test_root_must_be_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.py'
            path.write_text('value = 1')
            with self.assertRaises(ValueError):
                checks.scan_repo_for_crypto_issues(path)

    def test_source_digest_preserves_crlf_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = b"import hashlib\r\nhashlib.md5(data)\r\n"
            (root / 'sample.py').write_bytes(raw)
            result = checks.scan_repo_for_crypto_issues(root)
            self.assertTrue(result['findings'])
            self.assertEqual(result['findings'][0]['evidence']['source_sha256'],
                             hashlib.sha256(raw).hexdigest())

    def test_nonce_column_counts_unicode_characters(self):
        from decrypto_nonce_checks import check_python_aead_nonces
        source = ('from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n'
                  'aead = AESGCM(key)\n'
                  "label = 'é'; aead.encrypt(b'123456789012', data, None)\n")
        entries = check_python_aead_nonces(source, 'sample.py')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['evidence']['column'], 14)

    def test_excluded_directories_are_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.venv').mkdir()
            (root / '.venv' / 'secret.py').write_text('md5')
            (root / 'sample.py').write_text('md5')
            result = checks.scan_repo_for_crypto_issues(root)
            self.assertEqual(result['meta']['files_inspected'], 1)
            self.assertEqual({f['evidence']['file'] for f in result['findings']}, {'sample.py'})

    def test_source_read_is_bounded_even_if_file_grows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'sample.py').write_text('md5')
            import io
            stream = io.BytesIO(b'x' * 1_048_577)
            with patch.object(Path, 'open', return_value=stream):
                result = checks.scan_repo_for_crypto_issues(root)
            self.assertEqual(result['meta']['files_inspected'], 0)
            self.assertEqual(result['meta']['skipped'][0]['file'], 'sample.py')

    def test_symlinked_source_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'
            root.mkdir()
            outside = Path(tmp) / 'outside.py'
            outside.write_text('md5')
            try:
                (root / 'link.py').symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks unavailable')
            result = checks.scan_repo_for_crypto_issues(root)
            self.assertEqual(result['meta']['files_inspected'], 0)
            self.assertEqual(result['meta']['skipped'][0]['file'], 'link.py')
