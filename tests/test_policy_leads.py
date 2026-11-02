"""Decrypto synthetic policy controls: no external requests or real secrets."""
import json
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from decrypto_assumption_scan import observe, cors_checks, inspect_openapi, scan, MARKER_ORIGIN
from decrypto_validation import metadata, evaluate_cors_pair, ORIGINS


def headers(**values):
    result = Message()
    for name, value in values.items():
        result[name.replace('_', '-')] = value
    return result


class TestPolicyLeads(unittest.TestCase):
    def rules(self, h, private=False, url='https://fixture.invalid/'):
        return {f['rule'] for f in observe(url, 200, h, private)}

    def test_hsts_controls(self):
        for value, expected in [('max-age=31536000; includeSubDomains', False),
                                ('max-age=0', True), ('max-age=abc', True),
                                ('max-age=1; max-age=2', True)]:
            with self.subTest(value=value):
                self.assertEqual('TLS-HSTS' in self.rules(headers(Strict_Transport_Security=value)), expected)
        self.assertNotIn('TLS-HSTS', self.rules(Message(), url='http://localhost/'))

    def test_cookie_controls_and_redaction(self):
        for value, expected in [('session=SYNTHETIC; Secure; HttpOnly; SameSite=Lax', False),
                                ('session=SYNTHETIC; Secure; HttpOnly; SameSite=bogus', True),
                                ('session=SYNTHETIC; HttpOnly; SameSite=None', True),
                                ('__Host-session=SYNTHETIC; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=fixture.invalid', True)]:
            findings = observe('https://fixture.invalid/', 200, headers(Set_Cookie=value), False)
            self.assertEqual(any(f['rule'].startswith('SESSION-COOKIE') for f in findings), expected)
            self.assertNotIn('SYNTHETIC', json.dumps(findings))

    def test_cache_controls(self):
        for value, expected in [('public', True), ('s-maxage=60', True), ('s-maxage=0', False),
                                ('public, no-store', False), ('public, private', False),
                                ('public, no-cache', False), ('x-public=yes', False)]:
            with self.subTest(value=value):
                self.assertEqual('PRIVATE-CACHE' in self.rules(headers(Cache_Control=value), True), expected)
                self.assertNotIn('PRIVATE-CACHE', self.rules(headers(Cache_Control=value)))
        h = headers(Cache_Control='public')
        h['Cache-Control'] = 'private'
        self.assertNotIn('PRIVATE-CACHE', self.rules(h, True))

    def test_cors_browser_controls(self):
        h = headers(Access_Control_Allow_Origin=MARKER_ORIGIN, Access_Control_Allow_Credentials='true', Cache_Control='public')
        self.assertEqual(len(cors_checks('https://fixture.invalid/', 200, h)), 2)
        h['Vary'] = 'Accept-Encoding'
        h['Vary'] = 'Origin'
        self.assertEqual(len(cors_checks('https://fixture.invalid/', 200, h)), 1)
        del h['Vary']
        h['Vary'] = '*'
        self.assertEqual(len(cors_checks('https://fixture.invalid/', 200, h)), 1)
        h.replace_header('Access-Control-Allow-Credentials', 'TRUE')
        self.assertNotIn('CORS-TRUST', {f['rule'] for f in cors_checks('https://fixture.invalid/', 200, h)})
        h['Access-Control-Allow-Origin'] = MARKER_ORIGIN
        self.assertEqual(cors_checks('https://fixture.invalid/', 200, h), [])
        samples = [metadata(origin, 200, headers(Access_Control_Allow_Origin=origin, Access_Control_Allow_Credentials='TRUE')) for origin in ORIGINS]
        self.assertFalse(evaluate_cors_pair('https://fixture.invalid/', samples)['evidence']['both_untrusted_origins_reflected_with_credentials'])

    def test_openapi_inheritance_optional_and_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'synthetic.json'
            spec = {'openapi': '3.0.3', 'components': {'securitySchemes': {'bearer': {'type': 'http', 'scheme': 'bearer'}}}, 'security': [{'bearer': []}], 'paths': {'/fixture': {'post': {}}}}
            for security, expected in [(None, False), ([], True), ([{}, {'bearer': []}], True), ([{'bearer': []}], False)]:
                spec['paths']['/fixture']['post'] = {} if security is None else {'security': security}
                path.write_text(json.dumps(spec))
                findings, _ = inspect_openapi(path)
                self.assertEqual(bool(findings), expected)
            spec['paths']['/fixture'] = {'$ref': './not-fetched.json', 'post': {}}
            path.write_text(json.dumps(spec))
            self.assertEqual(inspect_openapi(path)[0], [])
            spec['paths'] = []
            path.write_text(json.dumps(spec))
            with patch('decrypto_assumption_scan.send') as send:
                with self.assertRaises(ValueError):
                    scan(['https://fixture.invalid/'], set(), openapi=path)
                send.assert_not_called()

    def test_nonfinite_limits(self):
        for kwargs in [{'delay': float('nan')}, {'timeout': float('inf')}]:
            with self.assertRaises(ValueError):
                scan([], set(), **kwargs)
