# Security-project — Decrypto

Decrypto is an assumption-driven static and live-audit toolkit for finding unintended
cryptography implementation bugs and other crypto-related anti-patterns in code.

This project is Python-first. The goal is to perform repo-wide crypto lead detection
with Python tooling and Python-based sample implementations, while keeping the project
focused on responsible review rather than confirmed exploitation.

This project is a lead-generation tool for security reviewers and SecOps teams. It
is NOT a confirmed vulnerability scanner or a cryptographic validator. Findings
are hypothesis-driven and require owner validation before reporting or remediation.

Key goals

- Detect likely crypto implementation mistakes (hardcoded keys, weak hashes,
  insecure RNG, TLS bypasses, misused cipher APIs) across a repository snapshot
  and optionally as read-only live HTTP checks for authorized targets.
- Produce concise, redacted, reproducible leads that a SecOps engineer or
  security reviewer can triage and validate.
- Keep the project Python-native, using Python implementations for secure crypto
  examples and relying on Python tooling for static scanning.
- Avoid storing secret values, response bodies, cookie names/values, redirect
  destinations, or session tokens in outputs.

What it includes

- decrypto_assumption_scan.py — the main, read-only assumption-driven HTTP and
  OpenAPI auditor. Designed to run against explicitly authorized HTTP(S) URLs and
  local OpenAPI JSON files only.
- decrypto_crypto_checks.py — repo-wide static scanner for crypto implementation
  anti-patterns in Python source files (and conservative text-based patterns for other source types).
- secure_crypto_examples.py — Python-native secure crypto helper examples using
  `secrets` and `hashlib` for random byte generation, password-derived key material,
  and HMAC verification.
- tests/ — unit tests for the scanner and the static crypto checks.
- .github/workflows/ci.yml — CI workflow that runs the Python unit tests.

Supported checks (snapshot static analysis)

The static crypto checks are heuristics that report leads for manual review. They
include but are not limited to:

- Quoted long hex/base64 literals and embedded PEM private keys (bare identifiers are not treated as secrets)
- Use of weak or deprecated hashes (md5, sha1, md4)
- Weak ciphers or insecure modes (ECB, RC4, DES, 3DES)
- Use of non-cryptographic RNGs or explicit PRNG seeding (random.random(), random.seed())
- TLS verification bypass (verify=False, _create_unverified_context)
- PBKDF2 usage (flagged for manual verification of iterations and salt)
- Potential "rolling-your-own" use of low-level cipher APIs
- Python AST leads for syntactically fixed AES-GCM / ChaCha20-Poly1305 encryption nonces (no secret values recorded)

Python secure crypto examples

The repo now includes a Python-safe crypto reference module that demonstrates
trusted patterns instead of insecure JavaScript equivalents:

- `secrets.token_bytes()` for cryptographic randomness
- `hashlib.pbkdf2_hmac()` for password-derived keys with explicit iteration counts
- `hmac.compare_digest()` for constant-time comparison
- Explicit hashing/HMAC examples that avoid unsafe defaults

## Paired CORS verification (authorized websites only)

For explicit permissioned URLs, use `--verify-cors` to compare two benign,
credential-free GET requests with different Origin values. This is a bounded,
read-only **policy consistency** check, not an exploitation test or proof of
cross-account access. Up to eight URLs (24 requests) can be checked per run.

```bash
python3 decrypto_assumption_scan.py --url https://your-authorized-domain.example/ \\
  --authorized --verify-cors --out cors_verification
```

Review the `paired_cors_verification` entries in the JSON report. A positive
result only establishes reflected response headers for the two observations;
actual sensitive data exposure, authentication and browser behavior require
separately authorized validation using owner-controlled test resources.

## Website testing quick start

The live auditor is already implemented in `decrypto_assumption_scan.py`. Run it locally
against HTTPS endpoints **you own or are explicitly authorized to assess**. The
`--authorized` flag affirms permission; it does not grant permission.

```bash
python3 decrypto_assumption_scan.py \
  --url https://your-authorized-domain.example/ \
  --authorized --cors --out site_audit
```

Read the results in `site_audit.json` and `site_audit.md`. Add explicit
`--url` flags (up to 12) for additional in-scope endpoints, and use
`--private-url` for a URL declared private by its owner. The tool does
not crawl a whole domain or test arbitrary URLs automatically.

The scanner sends a HEAD request per public URL and optionally an additional
GET with a harmless Origin header for `--cors`. A declared private URL uses
an anonymous GET instead of HEAD. It never follows redirects or stores response
bodies. HTTPS is required for non-loopback targets; query strings and embedded
credentials are rejected. A fragment is discarded because the browser does not
send it. The command limits requests and adds delays.

**Offline website test, without touching an external service:**

```bash
python3 -m unittest tests.test_website_cli -v
```

This starts a temporary HTTP server on 127.0.0.1, exercises the real CLI,
checks that JSON/Markdown results are created and redacted, and confirms
authorization is required. Static cryptographic checks, including nonce
hypotheses, require access to source files; they are not inferred from HTTP
response headers.

## Authorized bug-bounty review

Decrypto can prepare review leads for a bug-bounty program you are already
allowed to test. It does not submit reports, contact program platforms, or
decide whether you have permission. `--authorized` is your assertion that you
may test the listed assets. A scope file is the program's asset list as you
recorded it; it is not proof of permission.

Copy `examples/bounty-scope.local.json` and replace it with the hosts, URLs,
wildcards, and exclusions from that program. The checked-in example allows
loopback names only (`127.0.0.1`, `localhost`, `::1`) so it can be practiced
against a local fixture. Do not add an asset you are not allowed to test.
Bare hosts match any scheme and port. A URL matches that scheme, host, and
port; a trailing `/*` covers one path prefix. `*.name.example` matches
subdomains of any depth and does not match the apex. Exclusions win. `*` and
other rules that would cover unrelated hosts are rejected.

Run the live auditor only against an in-scope local or authorized asset:

```bash
python3 decrypto_assumption_scan.py \
  --scope ./my-program-scope.json \
  --url http://127.0.0.1:8765/ \
  --authorized \
  --delay 0.5 \
  --out bounty_review
```

### Local OWASP Juice Shop

Use this only for a Juice Shop process you started yourself, usually at
`http://127.0.0.1:3000/` or `http://localhost:3000/`. The checked-in scope
allows those loopback origins on port 3000 and nothing else. A public demo
host is out of scope and is refused before any request. If your instance
uses another port, change the port in a copy of the scope file. Paste the
browser URL if you want; `http://localhost:3000/#/score-board` is scanned as
`http://localhost:3000/` because the fragment is not sent.

```bash
python3 decrypto_assumption_scan.py \
  --scope examples/bounty-scope.juice-shop.local.json \
  --url http://127.0.0.1:3000/ \
  --authorized \
  --all-checks \
  --delay 0.5 \
  --out juice_shop_review
```

`--all-checks` runs every read-only check Decrypto already has: response
headers, cookie flags, paired CORS observations, redirect-parameter
reflection, and HEAD probes of well-known sensitive paths. TLS is included
and applies only when the URL is HTTPS. Leads stay unconfirmed. This does
not submit Juice Shop challenges and does not send injection, XSS, or
access-bypass payloads. Juice Shop often answers 200 for unknown paths, so
a sensitive-path lead still needs you to confirm the response in your local
session.

An explicit URL outside the scope is refused before any request is sent.
Sensitive-path and redirect probes that fall outside the scope are skipped and
listed as not contacted. Pass `--check-sensitive-paths` only when those paths
are in scope for the host you are allowed to test. The command writes
`bounty_review.json`, `bounty_review.md`, and `bounty_review.bounty.md`.

For source that belongs to the same program, point the static scanner at a
local tree and name the in-scope asset. `code_assets` in the scope file can
name a local label that is not a URL:

```bash
python3 decrypto_crypto_checks.py \
  --scope ./my-program-scope.json \
  --asset 127.0.0.1 \
  --out crypto_review \
  ./path/to/authorized/local/source
```

`crypto_review.bounty.md` is a submission draft. Each lead has a stable finding
ID (rule plus asset location, so two sensitive paths on one host do not
collide), the program asset, the location, taxonomy with CWE when the rule has
one, redacted evidence, reproduction notes that describe the observation, and
the assumption about impact. Evidence keeps file locations, statuses, and
SHA-256 digests. It does not include matched secret literals, response bodies,
or cookie values. Every lead stays **UNCONFIRMED**. The draft's confirmed
count is zero. Validate impact yourself, inside the program rules, before
filing. Do not send the draft to a program whose assets you did not test, and
do not describe a lead as a confirmed vulnerability unless a separate
authorized validation actually reproduced the impact.

Live HTTP/OpenAPI checks (assumption-driven)

- HSTS missing on HTTPS endpoints
- Session-like cookies missing Secure/HttpOnly/SameSite attributes
- CORS credential reflection + caching leads (see paired CORS verification above)
- Missing framing protection, missing `nosniff`, and Server/X-Powered-By version banners
  (always on; no extra requests)
- `--check-redirects`: open-redirect reflection in the Location header (never followed)
- `--check-sensitive-paths`: HEAD-only probe of `/.git/HEAD`, `/.env`, `/.aws/credentials`,
  `/wp-config.php.bak` (2xx is a lead; SPA catch-alls cause false positives)
- `--check-tls`: certificate expiry and weak negotiated protocol via one handshake per host
- `--domain example.com`: passively finds
  subdomains (crt.sh certificate-transparency logs + DNS resolution, via
  `decrypto_subdomain_scan.py`) and adds up to `--max-subdomains` (default 5, max 15) to the
  scan. Requires `--authorized`; the discovery step never contacts the subdomains itself.
- ### Dictionary DNS discovery (sfuzzer-style)

`decrypto_sfuzzer.py` implements the wordlist-based DNS subdomain discovery idea behind NITE Team 4's sfuzzer. It discovers names such as `admin.example.com`; it is not an HTTP path fuzzer for `/admin`, `robots.txt`, or `index.php`.

Every run requires `--authorized` and a local `--scope` file. Only candidate hostnames whose root URL is allowed by that scope are queried. Lookups are sequential, with a minimum 0.5-second delay and a hard cap of 500 candidates (default 100). The tool makes DNS lookups only; it sends no HTTP requests, probes no ports, and records address-family labels instead of IP addresses. The built-in wordlist is small; `--wordlist` accepts a local UTF-8 file with one DNS label per line.

```bash
python3 decrypto_sfuzzer.py \
  --domain your-authorized-domain.example \
  --scope ./my-program-scope.json \
  --authorized --delay 0.5 --max-candidates 100 \
  --out subdomain_candidates.json
```

Each matching hostname is an unconfirmed DNS observation. Review the scope and owner authorization again before using any hostname for HTTP testing. Unit tests mock DNS resolution and contact no external service.

Private-endpoint assumptions (gated by observable auth signals such as WWW-Authenticate or session-like Set-Cookie)
- Offline OpenAPI contract inspection (API key-in-URL, mutating operations without documented security requirements)

Bug-class taxonomy: every finding carries a `taxonomy` object (category, subtype, CWE,
OWASP Top 10 2021) from `decrypto_taxonomy.py`, and reports include `findings_by_category`.
Variants covered include CSP weaknesses (missing, `unsafe-inline`, `unsafe-eval`, wildcard
sources, missing `object-src`/`base-uri`), Referrer-Policy and Permissions-Policy gaps,
framework version headers, CORS wildcard, twelve sensitive-path kinds (version control,
environment files, cloud credentials, backups, debug endpoints), and static crypto variants
(ECB mode, deprecated TLS protocols, small RSA keys, low KDF iterations, JWT `none`,
hardcoded IV/nonce). This is a bounded, passive rule set, not every possible bug class; it
does not cover injection, XSS, IDOR or logic flaws, which need authorized manual testing.

The assumption model on each lead records the assumption, the observation, whether that configuration is visible in the collected data (`mechanism_observed`), and what would falsify the lead. `impact_shown` is false. A visible header, redirect, certificate, or source pattern is not an exploitability proof. Status stays UNCONFIRMED until the owner validates real-world impact. The tool still sends no injection/XSS/SQLi payloads, brute-force, IDOR, or load tests.

Important safety and privacy constraints

- Live HTTP checks are disabled unless you pass `--authorized` and provide
  explicit --url values. Do not run the live scanner against assets you do not
  have permission to test.
- The tool never follows redirects and does not send exploit payloads.
- The tool does not store response bodies, cookie values, or other secrets. All
  evidence in reports is redacted or limited to non-sensitive metadata.

Usage examples

- Run static crypto checks against the current repository:

  python3 -c "from decrypto_crypto_checks import scan_repo_for_crypto_issues; import json, pathlib; print(json.dumps(scan_repo_for_crypto_issues(pathlib.Path('.')), indent=2))"

- Run the secure crypto helper examples:

  python3 secure_crypto_examples.py

- Run the HTTP/OpenAPI auditor (explicit authorization required):

  python3 decrypto_assumption_scan.py \
    --url https://example.com/health \
    --url https://example.com/user/profile \
    --private-url https://example.com/user/profile \
    --authorized \
    --cors \
    --out decrypto_findings

- Run unit tests locally:

  python tools/run_tests.py

CI

The CI workflow runs the unit tests on Python 3.9 and 3.12. Tests use temporary
files and a loopback HTTP fixture only; CI does not audit external targets.
Python 3.9 is a compatibility check, not a deployment recommendation; use a
supported Python release for normal operation.

The security workflow runs Gitleaks, a `pip-audit` check, and Python CodeQL on
pushes to `main`, pull requests, and a weekly schedule. The workflow requests
contents read and security-events write. Actions are pinned to major version
tags and tracked by Dependabot. There are no third-party Python runtime
dependencies; `pip-audit` in this workflow inspects the runner environment.
When adding dependencies, commit a versioned dependency manifest and point the
audit at that manifest.

Repository administrators should require the CI and security checks in branch
protection before merging. Workflow files alone do not enforce merge protection.
CodeQL availability also depends on the repository's GitHub security settings.

### Controlled cross-account read validation

`decrypto_access_validation.py` is a separate, opt-in validator for a specific
access-control failure. It does not discover object IDs or exploit arbitrary
findings. Use it only where the program permits authenticated testing with two
accounts you control, against GET endpoints that have no side effects.

1. Create one private synthetic record in account A and another in account B.
   Give each a different unpredictable marker (16–256 UTF-8 bytes), stored in the
   record content, not its URL. Confirm policy says each record is owner-only.
2. Copy `examples/access-validation.json`. Supply both exact record URLs on the
   same origin, the two markers, and the applicable permission reference.
3. Set the named environment variables to the respective bearer credentials in
   your local environment. Do not put credentials in JSON, command arguments,
   source control, or reports.
4. Run:

```bash
python decrypto_access_validation.py --config my-validation.json --authorized --out validation-result.json
```

The output file must not already exist. Keep your config and test-account
mapping privately so you can reproduce the request sequence. Requests use GET
and bearer authentication only: A reads A's record, B reads B's record,
anonymous reads A's record, then B reads A's record. The sequence runs twice,
with a one-second delay between requests, for at most eight requests.
Failed controls stop the run early. No redirects, ID enumeration, state-changing
requests, cookie storage, or proxy environment settings are used.

| Result | Meaning |
| --- | --- |
| `reproduced_cross_account_read` | B retrieved A's synthetic marker twice; both own-record controls passed and anonymous requests were denied |
| `not_reproduced` | Both cross-account probes were denied with passing controls |
| `inconclusive` | Controls failed, responses were incomplete/redirected, or results were inconsistent |

Reports retain role-labelled observations, statuses, byte counts and body hashes.
They omit credentials, response bodies, markers, and raw URLs. Reads are bounded
to 64 KiB plus one byte; oversized or encoded responses cannot establish success.
URLs with query strings are currently unsupported. Ownership, different account
identities, permission and intended policy remain operator assertions. A successful
run demonstrates disclosure of the supplied synthetic marker; it does not identify
the root cause, validate other exploit classes, or guarantee a bounty.

### Authentication and sensitive output

The main auditor sends anonymous requests; it does not accept passwords, session
cookies or bearer tokens. `--authorized` is an operator permission assertion,
not an authentication mechanism. URL validation errors do not echo rejected
credential-bearing URLs. The standalone crypto demonstration prints sizes and
a verification result instead of derived key material. Reports still contain
endpoint paths and selected metadata: do not put secrets in URL paths or assume
all arbitrary server-provided metadata is automatically sanitized.

Static source reports include file locations and SHA-256 digests of the exact
input bytes, but no matched source excerpts or literal values. This replaces
the former `match_excerpt` evidence field: consumers should use `file`, `line`,
`column`, and `source_sha256` to inspect the local source. File names remain
visible and should not contain secrets. AEAD nonce findings carry stable
location-based IDs and taxonomy metadata, like other static findings.

Static scan metadata includes `skipped` paths with reasons and the configured
`excluded_directories`. Oversized files (over 1 MiB), unreadable or non-UTF-8
source, and links are reported as skipped. Excluded dependency directories are
pruned before traversal. Only Python and JavaScript source selected by the
language filter is counted; a scan with no findings does not establish that
skipped or excluded code is safe.

Limitations and next steps

### Additional Python bug-finding checks

The offline repository scanner now includes four AST-based rule families:

| Rule | Observed pattern | Safer control |
| --- | --- | --- |
| `PY-UNSAFE-DESERIALIZATION` | `pickle`, `_pickle`, or `dill` object loading | Data-only parsing such as `json.loads` |
| `PY-UNSAFE-YAML` | Unsafe YAML APIs or `load/load_all` without a recognized safe loader | `safe_load`, `SafeLoader`, or `CSafeLoader` |
| `PY-SHELL-EXECUTION` | `os.system/popen`, subprocess shell helpers, or explicit `shell=True` | Argument lists with `shell=False` |
| `PY-DYNAMIC-EVALUATION` | Builtin `eval/exec`, including imported aliases | Constrained parsing or explicit dispatch |

Run all existing crypto checks and these new Python checks together:

```bash
python decrypto_crypto_checks.py /path/to/authorized/local/source
```

No scanned source is imported or executed. New findings include CWE/category
metadata, remediation, source locations, and hashes without source literals.
Trusted uses of these APIs can be intentional; no input provenance, taint flow,
exploitability, or runtime reachability is established.

The new resolver recognizes unambiguous imports in module and function scopes.
It suppresses rebound names conservatively and does not analyze class bodies,
methods, or comprehension scopes. Star imports, dynamic imports, monkey-patching,
wrapper functions, and complex control flow are not resolved. Safe alternatives
in the table suppress these particular rules; they are not a general security
guarantee. Syntax or AST resource errors are reported as partial coverage
(`regex checks only`) rather than silently counted as complete AST analysis.

- AEAD nonce analysis is source-only: it does not establish runtime key/nonce reuse. Names are resolved per lexical scope; parameters, loop targets, and rebinding are not treated as fixed nonces. A value stays fixed after a branch only when every branch agrees. Attribute receivers such as `self.aead`, helper return values, and star imports from other modules are not resolved.
- The static crypto checks are intentionally conservative regex-based heuristics, supplemented by a narrow Python AST rule.
  They will produce false positives and require language-aware analysis to
  improve signal-to-noise.
- No commit-history scanning is performed by default. If you want history-based
  secret detection (e.g., scanning past commits for leaked keys) confirm first;
  that is slower and may require additional permissions.
- The tool is not a replacement for a full cryptographic code review or formal
  security assessment. Use findings as leads to guide manual review.

Contributing

Contributions, improved detection rules, language-aware analyzers, and better
false-positive filtering are welcome. Please open pull requests and include
unit tests for new detections.

License

Provided as-is for authorized security review and responsible disclosure
workflows.


### Decrypto 1.3 policy leads and synthetic validation

The authorized read-only scanner now reviews invalid/disabled HSTS max-age,
SameSite values and None/Secure combinations, and __Host-/__Secure- cookie
requirements. Cookie names and values remain in memory only. Prefix failures
may mean a browser rejects a cookie, rather than exposing a session.

Shared-cache checks use exact directive names across repeated fields and suppress
leads for private, no-store, no-cache, or zero s-maxage policies. An explicitly
owner-declared private endpoint can produce a cache lead without setting a cookie.
CORS checks respect case-sensitive credential permission, reject duplicate
allow-origin/credentials fields, and respect repeated Vary fields and Vary: *.
Cache evidence is boolean metadata, never raw Cache-Control values.

Offline OpenAPI review recognizes inherited security and anonymous alternatives
(`security: []` or an empty requirement object in an OR list). Intentionally public
writes still need owner review. Unresolved operation/path references are skipped;
external references are never fetched. Malformed contract structures fail before
any HTTP requests. This is a targeted review, not full OpenAPI schema validation.

Reproduce the synthetic controls with `python -m unittest discover -s tests -v`.
The tests cover positive/negative policy pairs, redaction, invalid input and the
loopback-only CLI fixture. Existing standalone test functions are included in
unittest discovery. No real website, credential, or customer data is needed.
Leads remain unconfirmed; inherited HSTS, browser cookie rules, intended public
operations and actual cache/CDN behavior require owner validation. Missing
headers and contract declarations do not prove exploitable impact. Keep generated
reports confidential and share only through the owner's approved disclosure channel.

