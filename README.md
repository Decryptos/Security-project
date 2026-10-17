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

Python secure crypto examples

The repo now includes a Python-safe crypto reference module that demonstrates
trusted patterns instead of insecure JavaScript equivalents:

- `secrets.token_bytes()` for cryptographic randomness
- `hashlib.pbkdf2_hmac()` for password-derived keys with explicit iteration counts
- `hmac.compare_digest()` for constant-time comparison
- Explicit hashing/HMAC examples that avoid unsafe defaults

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
    --private-url https://example.com/user/profile \
    --authorized \
    --cors \
    --out decrypto_findings

- Run unit tests locally:

  python -m unittest discover -v

CI

A GitHub Actions workflow (.github/workflows/ci.yml) runs the Python unit tests.

Limitations and next steps

- The static crypto checks are intentionally conservative regex-based heuristics.
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
