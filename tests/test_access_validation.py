"""Controlled synthetic HTTP validation, never external bounty targets."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import threading
import unittest
from unittest.mock import patch

import decrypto_access_validation as validation

OWNER = 'synthetic-owner-marker-9384'
OTHER = 'synthetic-other-marker-2481'
ENV = {'OWNER_TEST_TOKEN': 'owner-fixture-token', 'OTHER_TEST_TOKEN': 'other-fixture-token'}


def config(base='http://127.0.0.1:1234'):
    return {'owner_record_url': base + '/owner-record', 'other_record_url': base + '/other-record',
            'owner_marker': OWNER, 'other_marker': OTHER,
            'owner_token_env': 'OWNER_TEST_TOKEN', 'other_token_env': 'OTHER_TEST_TOKEN',
            'authorization_reference': 'local synthetic lab', 'synthetic_records': True,
            'expected_policy': 'owner-only'}


class Handler(BaseHTTPRequestHandler):
    mode = 'vulnerable'
    requests = []
    def log_message(self, *args):
        pass
    def do_GET(self):
        token = self.headers.get('Authorization')
        self.server.requests.append((self.path, token))
        if self.server.mode == 'redirect':
            self.send_response(302)
            self.send_header('Location', '/unexpected')
            self.end_headers()
            return
        if self.path == '/other-record' and token == 'Bearer ' + ENV['OTHER_TEST_TOKEN']:
            status, body = 200, OTHER.encode()
        elif self.path == '/owner-record' and token == 'Bearer ' + ENV['OWNER_TEST_TOKEN']:
            status, body = 200, OWNER.encode()
        elif self.path == '/owner-record' and token == 'Bearer ' + ENV['OTHER_TEST_TOKEN'] and self.server.mode == 'vulnerable':
            status, body = 200, OWNER.encode()
        else:
            status, body = 403, b'denied'
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body)


class TestAccessValidation(unittest.TestCase):
    @contextlib.contextmanager
    def server(self, mode):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.mode, server.requests = mode, []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, config('http://127.0.0.1:' + str(server.server_port))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def run_local(self, cfg):
        with patch.object(validation.time, 'sleep'):
            return validation.validate(cfg, authorized=True, environ=ENV)

    def test_vulnerable_fixture_reproduces_cross_account_read(self):
        with self.server('vulnerable') as (server, cfg):
            result = self.run_local(cfg)
            self.assertEqual(result['status'], 'reproduced_cross_account_read')
            self.assertEqual(len(server.requests), 8)
            self.assertEqual(result['requests_sent'], 8)
            rendered = json.dumps(result)
            for secret in (OWNER, OTHER, *ENV.values(), cfg['owner_record_url']):
                self.assertNotIn(secret, rendered)

    def test_patched_fixture_not_reproduced(self):
        with self.server('patched') as (server, cfg):
            self.assertEqual(self.run_local(cfg)['status'], 'not_reproduced')
            self.assertEqual(len(server.requests), 8)

    def test_redirect_is_not_followed_or_credential_forwarded(self):
        with self.server('redirect') as (server, cfg):
            result = self.run_local(cfg)
            self.assertEqual(result['status'], 'inconclusive')
            self.assertEqual(len(server.requests), 1)
            self.assertEqual(server.requests[0][0], '/owner-record')

    def test_authorization_required_before_network(self):
        with patch.object(validation, 'build_opener') as opener:
            with self.assertRaises(ValueError):
                validation.validate(config(), environ=ENV)
            opener.assert_not_called()

    def test_same_credentials_rejected(self):
        with self.assertRaises(ValueError):
            validation.prepare(config(), dict.fromkeys(ENV, 'same-token'))

    def test_scope_and_markers_rejected(self):
        for change in ({'other_record_url': 'https://different.example/record'},
                       {'owner_record_url': 'https://user:password@example.com/record'},
                       {'synthetic_records': False}, {'expected_policy': 'public'},
                       {'owner_marker': 'short'}, {'other_marker': OWNER},
                       {'owner_record_url': 'http://example.com/record'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validation.prepare({**config(), **change}, ENV)

    def test_anonymous_marker_or_failed_controls_never_confirm(self):
        good = {'status': 200, 'complete': True, 'marker_present': True}
        denied = {'status': 403, 'complete': True, 'marker_present': False}
        for samples in ([denied], [good, denied], [good, good, good]):
            with self.subTest(samples=samples), patch.object(validation, 'observe', side_effect=samples):
                result = self.run_local(config())
                self.assertEqual(result['status'], 'inconclusive')
                self.assertEqual(result['requests_sent'], len(samples))

    def test_inconsistent_repeat_not_confirmed(self):
        good = {'status': 200, 'complete': True, 'marker_present': True}
        denied = {'status': 403, 'complete': True, 'marker_present': False}
        with patch.object(validation, 'observe', side_effect=[good, good, denied, good, good, good, denied, denied]):
            self.assertEqual(self.run_local(config())['status'], 'inconclusive')

    def test_error_message_is_not_serialized(self):
        with patch.object(validation, 'observe', side_effect=OSError('secret-token')):
            result = self.run_local(config())
            self.assertEqual(result['status'], 'inconclusive')
            self.assertNotIn('secret-token', json.dumps(result))

    def test_oversized_response_cannot_confirm(self):
        response = io.BytesIO(OWNER.encode() + b'x' * validation.MAX_BODY)
        response.code, response.headers = 200, {}
        from unittest.mock import Mock
        result = validation.observe(Mock(open=Mock(return_value=response)),
                                    config()['owner_record_url'], ENV['OWNER_TEST_TOKEN'], OWNER.encode(), 1)
        self.assertFalse(result['complete'])
        self.assertFalse(result['marker_present'])
        self.assertIsNone(result['body_sha256'])
