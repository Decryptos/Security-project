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

- Hardcoded-looking long hex/base64 strings and embedded PEM private keys
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
credentials are rejected. The command limits requests and adds delays.

**Offline website test, without touching an external service:**

```bash
python3 -m unittest tests.test_website_cli -v
```

This starts a temporary HTTP server on 127.0.0.1, exercises the real CLI,
checks that JSON/Markdown results are created and redacted, and confirms
authorization is required. Static cryptographic checks, including nonce
hypotheses, require access to source files; they are not inferred from HTTP
response headers.

Live HTTP/OpenAPI checks (assumption-driven)

- HSTS missing on HTTPS endpoints
- Session-like cookies missing Secure/HttpOnly/SameSite attributes
- CORS credential reflection + caching leads
- Private-endpoint assumptions (gated by observable auth signals such as WWW-Authenticate or session-like Set-Cookie)
- Offline OpenAPI contract inspection (API key-in-URL, mutating operations without documented security requirements)

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

The CI workflow compiles Python sources, runs regression tests on Python 3.9,
3.12 and 3.14, and smoke-tests the CLI. The test runner fails if no tests are
discovered. Tests use temporary files and a loopback HTTP fixture only; CI does
not audit external targets. Python 3.9 is a compatibility check, not a deployment
recommendation; use a supported Python release for normal operation.

The security workflow runs Gitleaks secret scanning and Python CodeQL analysis
on pushes, pull requests and a weekly schedule. Actions are pinned to commit
SHAs and tracked by the existing GitHub Actions Dependabot configuration.
Workflow tokens default to read-only access; only the CodeQL job requests
security-event write access. Checkouts do not persist credentials, and Gitleaks
PR comments and artifact uploads are disabled.

There are currently no third-party Python runtime dependencies. The previous
bare `pip-audit` command audited the runner environment rather than a project
manifest, so that misleading job has been removed. When adding dependencies,
commit a versioned dependency manifest and add a manifest-targeted audit gate.

Repository administrators should require the CI and security checks in branch
protection before merging. Workflow files alone do not enforce merge protection.
CodeQL availability also depends on the repository's GitHub security settings.

Authentication and sensitive output

The auditor sends anonymous requests; it does not accept passwords, session
cookies or bearer tokens. `--authorized` is an operator permission assertion,
not an authentication mechanism. URL validation errors do not echo rejected
credential-bearing URLs. The standalone crypto demonstration prints sizes and
a verification result instead of derived key material. Reports still contain
endpoint paths and selected metadata: do not put secrets in URL paths or assume
all arbitrary server-provided metadata is automatically sanitized.

Limitations and next steps

- AEAD nonce analysis is source-only: it does not establish runtime key/nonce reuse and may miss aliases, helper functions, or complex control flow.
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
