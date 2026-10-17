# Security-project — Decrypto

Decrypto is a Python-first, assumption-driven crypto review toolkit.

It is designed to find likely cryptography implementation bugs and insecure patterns in codebases, while clearly labeling every result as an unconfirmed lead rather than a confirmed exploit.

This project is intended for authorized security review, internal SecOps triage, and responsible disclosure workflows. It is not a cryptographic validator and it is not a proof engine.

Project goals
- Scan source repositories for likely crypto implementation mistakes.
- Map findings to public CWE families for triage.
- Keep the project Python-native and easy to run from the command line.
- Keep outputs redacted and respectful of privacy and authorization boundaries.

Included files
- decrypto_assumption_scan.py: live HTTP/OpenAPI auditor for explicitly authorized targets.
- decrypto_crypto_checks.py: static repo scan for crypto misuses and anti-patterns.
- secure_crypto_examples.py: Python examples for secure randomness, PBKDF2, HMAC, and constant-time comparison.
- tests/test_crypto_checks.py: light regression tests for the static scanner.
- .github/workflows/ci.yml: Python CI workflow.

CWE-aware model

Findings are associated with public CWE categories so that they can be triaged consistently. The model is intentionally assumption-driven:
- a finding is a lead
- a CWE mapping is a likely category, not proof of exploitability
- a CVE association is optional context only, not a vulnerability confirmation

The primary static rule families are mapped to public CWE entries, including:
- Hard-coded keys / embedded private keys -> CWE-321
- Weak crypto algorithms -> CWE-327
- Insecure randomness -> CWE-330
- TLS validation bypass -> CWE-295
- Password hashing with insufficient work factor -> CWE-916

Static crypto checks

The static scanner checks for common implementation issues, including:
- hardcoded secret-like literals and PEM private keys
- weak hashes such as MD5, SHA-1, and MD4
- insecure ciphers or cipher modes such as ECB, DES, RC4, and 3DES
- insecure randomness such as random.random() and random.seed()
- TLS validation bypasses such as verify=False or _create_unverified_context
- PBKDF2 usage that should be reviewed for low iteration counts
- low-level cipher API usage that may indicate unsafe custom crypto

Live HTTP/OpenAPI checks

The live scanner is read-only and requires explicit authorization. It can check:
- missing HSTS on HTTPS endpoints
- session-like cookies missing Secure, HttpOnly, or SameSite flags
- CORS origin reflection and cache policy contradictions
- private endpoint assumptions
- offline OpenAPI contract issues such as API keys in URL query strings and mutating operations without security declarations

Safety and privacy

- Live checks require --authorized and explicit target URLs.
- Redirects are never followed.
- Response bodies, cookies, tokens, redirect destinations, and other sensitive raw values are not stored.
- Governing rule: no exploit payloads, no credential reuse, no cross-user validation.

Usage

Run the static crypto check against the current repository:

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

- The static checks are heuristic and may produce false positives.
- The model is intentionally conservative and does not claim exploitability without owner validation.
- Optional history-based review is available only as an opt-in, redacted review step.
- Public CVE references are not proof of impact; they are examples for context and triage.

License

Provided as-is for authorized security review and responsible disclosure work.
