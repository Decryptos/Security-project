"""Bounded, opt-in cross-account read validation using synthetic test records.

Account ownership and intended access policy are supplied by the operator.
Only explicit URLs are requested; redirects, discovery and writes are disabled.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, HTTPSHandler, build_opener

from decrypto_assumption_scan import NoRedirect, normalize_url

MAX_BODY = 65_536
FIELDS = {'owner_record_url', 'other_record_url', 'owner_marker', 'other_marker',
          'owner_token_env', 'other_token_env', 'authorization_reference',
          'synthetic_records', 'expected_policy'}


def prepare(config, environ):
    if not isinstance(config, dict) or set(config) != FIELDS:
        raise ValueError('Configuration fields do not match the documented template')
    if config['synthetic_records'] is not True or config['expected_policy'] != 'owner-only':
        raise ValueError('Requires synthetic records and an explicit owner-only policy')
    for name in FIELDS - {'synthetic_records'}:
        if not isinstance(config[name], str) or not config[name].strip():
            raise ValueError('Configuration text fields must be nonempty')
    urls = []
    for key in ('owner_record_url', 'other_record_url'):
        value = config[key]
        if any(ord(c) <= 32 or ord(c) == 127 for c in value):
            raise ValueError('URL contains whitespace or control characters')
        urls.append(normalize_url(value))
    if urls[0] == urls[1]:
        raise ValueError('Use distinct owner and other-account test records')
    from urllib.parse import urlsplit
    if urlsplit(urls[0]).netloc != urlsplit(urls[1]).netloc or urlsplit(urls[0]).scheme != urlsplit(urls[1]).scheme:
        raise ValueError('Both test records must use the same origin')
    markers = [config['owner_marker'], config['other_marker']]
    if any(not 16 <= len(m.encode('utf-8')) <= 256 for m in markers):
        raise ValueError('Use unique synthetic markers of 16 to 256 UTF-8 bytes')
    if markers[0] in markers[1] or markers[1] in markers[0] or any(m in u for m in markers for u in urls):
        raise ValueError('Markers must be distinct, non-overlapping, and absent from URLs')
    tokens = [environ.get(config[k], '') for k in ('owner_token_env', 'other_token_env')]
    if any(not t or len(t) > 8192 or any(ord(c) <= 32 or ord(c) >= 127 for c in t) for t in tokens):
        raise ValueError('Token environment variables must contain nonempty ASCII bearer tokens')
    if tokens[0] == tokens[1]:
        raise ValueError('Use distinct credentials for two separate test accounts')
    if any(m in t or t in m for m in markers for t in tokens):
        raise ValueError('Markers must not overlap credentials')
    return urls, [m.encode('utf-8') for m in markers], tokens


def observe(opener, url, token, marker, timeout):
    headers = {'User-Agent': 'Decrypto-Controlled-Validation/1.0',
               'Accept': 'application/json, text/plain', 'Accept-Encoding': 'identity',
               'Cache-Control': 'no-cache'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = Request(url, headers=headers, method='GET')
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        status = response.code
        # Never read redirect bodies or follow their Location headers.
        if 300 <= status < 400:
            return {'status': status, 'complete': False, 'marker_present': False,
                    'reason': 'redirect refused'}
        body = response.read(MAX_BODY + 1)
        complete = len(body) <= MAX_BODY
        encoding = response.headers.get('Content-Encoding', 'identity').lower().strip()
        if encoding not in ('', 'identity'):
            return {'status': status, 'complete': False, 'marker_present': False,
                    'reason': 'encoded response unsupported'}
        return {'status': status, 'complete': complete,
                'marker_present': marker in body if complete else False,
                'body_sha256': hashlib.sha256(body).hexdigest() if complete else None,
                'bytes_read': len(body)}


def validate(config, *, authorized=False, delay=1.0, timeout=6.0, environ=None):
    if not authorized:
        raise ValueError('Explicit --authorized permission assertion is required')
    if not math.isfinite(delay) or delay < .5 or not math.isfinite(timeout) or not 1 <= timeout <= 20:
        raise ValueError('Delay must be at least 0.5s and timeout between 1 and 20s')
    urls, markers, tokens = prepare(config, os.environ if environ is None else environ)
    opener = build_opener(NoRedirect(), ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()))
    result = {'check': 'controlled-cross-account-read', 'status': 'inconclusive',
              'recorded_at': datetime.now(timezone.utc).isoformat(),
              'target_sha256': hashlib.sha256(urls[0].encode()).hexdigest(),
              'authorization_reference_sha256': hashlib.sha256(config['authorization_reference'].encode()).hexdigest(),
              'expected_policy': 'owner-only', 'synthetic_records_asserted': True,
              'observations': [], 'requests_sent': 0,
              'limitations': [
                  'Account identities, ownership, authorization and intended policy are operator assertions.',
                  'Marker disclosure demonstrates access to the supplied synthetic record only.',
                  'No root cause, independent verification, bounty eligibility or payout is established.',
                  'Only explicit GET URLs are tested; bodies, tokens, markers and URL text are not retained.',
              ]}
    outcomes = []
    for round_number in (1, 2):
        for role, url, token, marker in (
            ('owner_control', urls[0], tokens[0], markers[0]),
            ('other_account_control', urls[1], tokens[1], markers[1]),
            ('anonymous_control', urls[0], None, markers[0]),
            ('cross_account_probe', urls[0], tokens[1], markers[0]),
        ):
            if result['requests_sent']:
                time.sleep(delay)
            result['requests_sent'] += 1
            try:
                sample = observe(opener, url, token, marker, timeout)
            except (OSError, ValueError, http.client.HTTPException) as exc:
                # Never serialize exception messages: they can contain request data.
                sample = {'complete': False, 'error_type': type(exc).__name__}
            result['observations'].append({'round': round_number, 'role': role, **sample})
            if not sample.get('complete'):
                result['reason'] = 'Incomplete observation; stopped without further requests'
                return result
            disclosed = 200 <= sample['status'] < 300 and sample['marker_present']
            denied = sample['status'] in (401, 403, 404) and not sample['marker_present']
            if role in ('owner_control', 'other_account_control') and not disclosed:
                result['reason'] = 'Authenticated record control did not pass'
                return result
            if role == 'anonymous_control' and not denied:
                result['reason'] = 'Anonymous denial control did not pass'
                return result
            if role == 'cross_account_probe':
                outcomes.append('disclosed' if disclosed else 'denied' if denied else 'unclear')
    if outcomes == ['disclosed', 'disclosed']:
        result['status'] = 'reproduced_cross_account_read'
        result['reason'] = 'Other test credentials retrieved the owner marker twice with all controls passing'
    elif outcomes == ['denied', 'denied']:
        result['status'] = 'not_reproduced'
        result['reason'] = 'Both cross-account probes denied access under the tested conditions'
    else:
        result['reason'] = 'Probe results were inconsistent or did not establish disclosure or denial'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--authorized', action='store_true')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        # Reserve the output before any requests, refusing overwrite.
        with args.config.open('rb') as stream:
            raw = stream.read(16_385)
        if len(raw) > 16_384:
            raise ValueError('Configuration exceeds 16 KiB')
        config = json.loads(raw)
        # Validate before creating output or contacting anything.
        if not args.authorized:
            raise ValueError('Explicit --authorized permission assertion is required')
        prepare(config, os.environ)
        with args.out.open('x', encoding='utf-8') as stream:
            result = validate(config, authorized=True)
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write('\n')
        print(result['status'])
        return 0
    except (OSError, ValueError):
        print('Validation failed: check configuration, credentials and output path; no sensitive details printed.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
