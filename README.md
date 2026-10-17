# Security-project — Decrypto

Decrypto is a Python-first, assumption-driven security research toolkit.

The project is designed to examine security assumptions, trust boundaries, and implementation patterns rather than simply matching known signatures or CVEs. It produces unconfirmed leads for manual triage and owner validation.

This project is intended for authorized review, internal SecOps triage, and responsible disclosure workflows. It is not a confirmed vulnerability scanner and not a cryptographic validator.

Goals
- Detect likely implementation mistakes in crypto-related code.
- Evaluate security assumptions in live HTTP and OpenAPI contexts.
- Keep outputs concise, redacted, and reproducible.
- Use public CWE families to structure findings without implying confirmed exploitability.
- Preserve a clear boundary between research leads and validated vulnerabilities.

Included files
- decrypto_assumption_scan.py — read-only HTTP/OpenAPI auditor for authorized targets.
- decrypto_crypto_checks.py — repo-wide static crypto checks with CWE-aware markup.
- secure_crypto_examples.py — Python examples for secure randomness and safe KDF/HMAC usage.
- tests/test_crypto_checks.py — unit testing for the static scanner.
- .github/copilot-instructions.md — guidance for assumption-driven research work.
- .github/workflows/ci.yml — CI workflow for Python tests.

Assumption-driven model

This project treats findings as hypotheses that arise from a violated or untested assumption. For example:
- a private endpoint should deny unauthenticated access
- a cookie used for session state should carry the correct browser boundaries
- a cache should not store identity-sensitive data in a shared cache
- a cryptographic implementation should not silently fall back to weak primitives

A contradiction between observed behavior and the expected assumption generates a lead. It is not a confirmed vulnerability until independently validated.

CWE mapping

Static crypto findings remain mapped to public CWE categories to support triage and reporting, including:
- CWE-321: hardcoded keys / private-key embedding
- CWE-327: weak or risky cryptographic algorithms
- CWE-330: insufficiently random values
- CWE-295: improper certificate validation
- CWE-916: insufficient password hashing work factor

Static crypto checks

The static scanner reports likely issues such as:
- hardcoded secret-like literals and embedded PEM private keys
- weak or deprecated hashes (MD5, SHA-1, MD4)
- insecure cipher use such as ECB, DES, RC4, and 3DES
- non-cryptographic randomness and PRNG seeding
- TLS validation bypasses such as verify=False or _create_unverified_context
- PBKDF2 use that should be reviewed for iteration count and salt handling
- low-level cipher APIs that may indicate custom or unsafe crypto

Live HTTP/OpenAPI checks

The live auditor is read-only and requires explicit authorization. It can assess:
- missing HSTS on HTTPS endpoints
- session-like cookies missing Secure, HttpOnly, or SameSite attributes
- potential CORS credential reflection and cache-policy mistakes
- private endpoints returning 2xx responses to unauthenticated requests
- offline OpenAPI contract issues such as API keys in URL queries or mutating operations without documented auth

Safety and privacy

- Live testing requires --authorized and explicit target URLs.
- Redirects are never followed.
- Response bodies, cookie values, tokens, redirect destinations, and secret-like strings are not stored.
- No exploit payloads are sent.
- No cross-account or credentialed attacks are performed.

Usage

Run static crypto checks against the current repository:

python3 -c "from decrypto_crypto_checks import scan_repo_for_crypto_issues; import json, pathlib; print(json.dumps(scan_repo_for_crypto_issues(pathlib.Path('.')), indent=2))"

Run the secure crypto examples:

python3 secure_crypto_examples.py

Run the live HTTP/OpenAPI auditor (requires explicit authorization):

python3 decrypto_assumption_scan.py \
  --url https://example.com/health \
  --private-url https://example.com/user/profile \
  --authorized \
  --cors \
  --out decrypto_findings

Run tests:

python -m unittest discover -v

Limitations

- Static checks are heuristic and can produce false positives.
- The model is intentionally conservative.
- Public CVE references are contextual only and are not proof of exploitability.
- Optional history-based review is opt-in and requires separate authorization.

License

Provided as-is for authorized security review and responsible disclosure work.
