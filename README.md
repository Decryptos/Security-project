# Security Project

This repository contains a hardened, assumption-driven HTTP/API auditor written in Python 3.9+ standard library only.

## What it does

`decrypto_assumption_scan.py` performs read-only, explicitly authorized checks for:

- missing HSTS on HTTPS targets
- session-like cookies missing `Secure`, `HttpOnly`, and `SameSite`
- cross-origin credential reflection and cache policy leads
- OpenAPI/Swagger contract review for risky auth placement and absent auth on mutating endpoints
- correlated assumption hypotheses without claiming exploitability

It intentionally reports leads, not confirmed vulnerabilities, and requires explicit authorization for live HTTP testing.

## Quick start

```bash
python3 decrypto_assumption_scan.py --help
```

Example:

```bash
python3 decrypto_assumption_scan.py \
  --url https://example.com/ \
  --private-url https://example.com/private \
  --authorized \
  --cors \
  --out decrypto_findings
```

## Files

- `decrypto_assumption_scan.py` — scanner implementation
- `tests/test_decrypto.py` — regression tests

## Security notes

- No response bodies, credentials, cookie names or values, redirect destinations, or session tokens are stored.
- Live HTTP testing is disabled unless `--authorized` is explicitly set.
- Redirects are never followed.
- The tool never sends exploit payloads or user data across unrelated accounts.
- Findings are treated as unconfirmed review leads that require owner validation.

## License

This project is provided as-is for authorized security review and responsible disclosure workflows.
