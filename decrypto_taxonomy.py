"""Bug-class taxonomy for Decrypto findings.

Maps every rule ID to a category, a subtype, a CWE and an OWASP Top 10 (2021)
bucket so reports can be grouped and filtered by bug class and variant.
Unknown rules fall back to "uncategorized" rather than being dropped.
"""

from __future__ import annotations

from typing import Any

# rule prefix -> (category, subtype, CWE, OWASP 2021)
TAXONOMY: dict[str, tuple[str, str, str, str]] = {
    # Transport security
    "TLS-HSTS": ("transport-security", "missing-or-invalid-hsts", "CWE-319", "A02"),
    "TLS-CERT-EXPIRY": ("transport-security", "expired-certificate", "CWE-298", "A02"),
    "TLS-WEAK-PROTOCOL": ("transport-security", "deprecated-tls-protocol", "CWE-326", "A02"),
    # Session / cookies
    "SESSION-COOKIE": ("session-management", "missing-cookie-attributes", "CWE-614", "A05"),
    # Access control
    "AUTH-BOUNDARY": ("access-control", "anonymous-access-to-private-endpoint", "CWE-306", "A01"),
    "OAS-WRITE-NO-AUTH": ("access-control", "mutating-operation-without-auth", "CWE-306", "A01"),
    "OAS-KEY-IN-URL": ("sensitive-data-exposure", "credential-in-url", "CWE-598", "A02"),
    # Caching
    "PRIVATE-CACHE": ("caching", "shared-cache-on-private-response", "CWE-524", "A05"),
    # CORS
    "CORS-TRUST": ("cross-origin", "credentialed-origin-reflection", "CWE-942", "A05"),
    "CORS-CACHE": ("cross-origin", "origin-policy-cache-key", "CWE-942", "A05"),
    "CORS-WILDCARD": ("cross-origin", "wildcard-origin", "CWE-942", "A05"),
    # Browser hardening headers
    "CLICKJACK-HEADERS": ("browser-hardening", "missing-framing-protection", "CWE-1021", "A05"),
    "MIME-SNIFF": ("browser-hardening", "missing-nosniff", "CWE-693", "A05"),
    "CSP-MISSING": ("browser-hardening", "missing-csp", "CWE-693", "A05"),
    "CSP-UNSAFE-INLINE": ("browser-hardening", "csp-unsafe-inline", "CWE-79", "A03"),
    "CSP-UNSAFE-EVAL": ("browser-hardening", "csp-unsafe-eval", "CWE-79", "A03"),
    "CSP-WILDCARD-SOURCE": ("browser-hardening", "csp-wildcard-or-scheme-source", "CWE-79", "A03"),
    "CSP-MISSING-DIRECTIVES": ("browser-hardening", "csp-missing-object-src-or-base-uri", "CWE-79", "A05"),
    "REFERRER-POLICY": ("browser-hardening", "missing-or-unsafe-referrer-policy", "CWE-200", "A05"),
    "PERMISSIONS-POLICY": ("browser-hardening", "missing-permissions-policy", "CWE-693", "A05"),
    # Information disclosure
    "SERVER-BANNER": ("information-disclosure", "server-version-banner", "CWE-200", "A05"),
    "FRAMEWORK-BANNER": ("information-disclosure", "framework-version-header", "CWE-200", "A05"),
    "SENSITIVE-PATH-EXPOSED": ("information-disclosure", "exposed-file-or-endpoint", "CWE-538", "A05"),
    # Redirects
    "OPEN-REDIRECT": ("redirect", "unvalidated-redirect-parameter", "CWE-601", "A01"),
    # Static crypto findings
    "CRYPTO-HARDKEY": ("cryptographic-failures", "hardcoded-key-or-secret", "CWE-798", "A02"),
    "CRYPTO-PEM-IN-CODE": ("cryptographic-failures", "private-key-in-repository", "CWE-321", "A02"),
    "CRYPTO-WEAK-HASH": ("cryptographic-failures", "weak-hash-algorithm", "CWE-328", "A02"),
    "CRYPTO-WEAK-CIPHER": ("cryptographic-failures", "weak-cipher-or-mode", "CWE-327", "A02"),
    "CRYPTO-ECB-MODE": ("cryptographic-failures", "ecb-block-mode", "CWE-327", "A02"),
    "CRYPTO-INSECURE-RNG": ("cryptographic-failures", "non-cryptographic-rng", "CWE-338", "A02"),
    "CRYPTO-TLS-WORKAROUND": ("cryptographic-failures", "tls-verification-disabled", "CWE-295", "A07"),
    "CRYPTO-TLS-OLD-PROTOCOL": ("cryptographic-failures", "deprecated-tls-protocol-in-code", "CWE-326", "A02"),
    "CRYPTO-PBKDF2": ("cryptographic-failures", "kdf-parameters-need-review", "CWE-916", "A02"),
    "CRYPTO-WEAK-KDF-ITERATIONS": ("cryptographic-failures", "low-kdf-iterations", "CWE-916", "A02"),
    "CRYPTO-SMALL-RSA-KEY": ("cryptographic-failures", "rsa-key-under-2048-bits", "CWE-326", "A02"),
    "CRYPTO-JWT-NONE-ALG": ("authentication", "jwt-alg-none", "CWE-347", "A02"),
    "CRYPTO-STATIC-IV": ("cryptographic-failures", "hardcoded-iv-or-nonce", "CWE-329", "A02"),
    "CRYPTO-POTENTIALLY-ROLLING": ("cryptographic-failures", "low-level-cipher-api", "CWE-327", "A02"),
    "CRYPTO-AEAD-STATIC-NONCE": ("cryptographic-failures", "aead-nonce-reuse", "CWE-323", "A02"),
}

_UNKNOWN = ("uncategorized", "unclassified", "", "")


def classify(rule: str) -> dict[str, str]:
    """Return taxonomy metadata for a rule ID, tolerating numeric suffixes (e.g. SESSION-COOKIE-2)."""
    candidate = rule
    while candidate:
        entry = TAXONOMY.get(candidate)
        if entry:
            break
        if "-" not in candidate:
            entry = _UNKNOWN
            break
        candidate = candidate.rsplit("-", 1)[0]
    else:
        entry = _UNKNOWN
    category, subtype, cwe, owasp = entry
    return {"category": category, "subtype": subtype, "cwe": cwe, "owasp_top10_2021": owasp}


def summarize(findings: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Count findings per category and subtype."""
    summary: dict[str, dict[str, int]] = {}
    for finding in findings:
        tax = finding.get("taxonomy") or classify(finding.get("rule", ""))
        bucket = summary.setdefault(tax["category"], {})
        bucket[tax["subtype"]] = bucket.get(tax["subtype"], 0) + 1
    return {cat: dict(sorted(sub.items())) for cat, sub in sorted(summary.items())}
