"""Bug-class taxonomy for Decrypto findings.

Maps every rule ID to a category, a subtype, a CWE, an OWASP Top 10 2021
bucket and the current OWASP Top 10:2025 bucket, so reports can be grouped
and filtered by bug class, variant and OWASP category. Unknown rules fall
back to "uncategorized" rather than being dropped.

Note on "2025 vs 2026": OWASP Top 10:2025 (released November 2025, finalized
January 2026) is the current, 8th edition. OWASP has not published a separate
2026 edition — per its historical ~4-year cadence (2017, 2021, 2025), the
next revision is not expected until roughly 2028-2029. Top 10:2025 is
therefore the correct, applicable reference for both 2025 and 2026.
"""

from __future__ import annotations

from typing import Any

# OWASP Top 10:2021 code -> OWASP Top 10:2025 code, per the official changes:
# Security Misconfiguration jumped from #5 to #2; Vulnerable/Outdated
# Components was broadened into the new "Software Supply Chain Failures";
# Server-Side Request Forgery (2021 A10, a standalone category) was folded
# into Broken Access Control; "Insecure Design" and the others shifted rank
# but kept their meaning.
OWASP_2021_TO_2025: dict[str, str] = {
    "A01": "A01:2025",  # Broken Access Control (unchanged; now also covers SSRF)
    "A02": "A04:2025",  # Cryptographic Failures
    "A03": "A05:2025",  # Injection
    "A04": "A06:2025",  # Insecure Design
    "A05": "A02:2025",  # Security Misconfiguration
    "A06": "A03:2025",  # Vulnerable/Outdated Components -> Software Supply Chain Failures
    "A07": "A07:2025",  # Authentication Failures (was "Identification and Authentication Failures")
    "A08": "A08:2025",  # Software or Data Integrity Failures
    "A09": "A09:2025",  # Security Logging and Alerting Failures
    "A10": "A01:2025",  # SSRF retired as standalone; absorbed into Broken Access Control
}

# rule prefix -> (category, subtype, CWE, OWASP 2021)
TAXONOMY: dict[str, tuple[str, str, str, str]] = {
    # Transport security
    "TLS-HSTS": ("transport-security", "missing-or-invalid-hsts", "CWE-319", "A02"),
    "TLS-CERT-EXPIRY": ("transport-security", "expired-certificate", "CWE-298", "A02"),
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
    # Active-payload-verified injection classes (opt-in, --enable-active-payloads)
    "SQLI-ERROR-BASED": ("injection", "sql-injection-error-based", "CWE-89", "A03"),
    "SQLI-TIME-BLIND": ("injection", "sql-injection-time-blind", "CWE-89", "A03"),
    "XSS-REFLECTED": ("injection", "cross-site-scripting-reflected", "CWE-79", "A03"),
    "COMMAND-INJECTION-TIME-BLIND": ("injection", "os-command-injection-time-blind", "CWE-78", "A03"),
    "PATH-TRAVERSAL": ("injection", "path-traversal-file-disclosure", "CWE-22", "A01"),
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
    category, subtype, cwe, owasp_2021 = entry
    return {
        "category": category,
        "subtype": subtype,
        "cwe": cwe,
        "owasp_top10_2021": owasp_2021,
        "owasp_top10_2025": OWASP_2021_TO_2025.get(owasp_2021, ""),
    }


def summarize(findings: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Count findings per category and subtype."""
    summary: dict[str, dict[str, int]] = {}
    for finding in findings:
        tax = finding.get("taxonomy") or classify(finding.get("rule", ""))
        bucket = summary.setdefault(tax["category"], {})
        bucket[tax["subtype"]] = bucket.get(tax["subtype"], 0) + 1
    return {cat: dict(sorted(sub.items())) for cat, sub in sorted(summary.items())}


def summarize_by_owasp(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings per OWASP Top 10:2025 category code (current standard; see module docstring)."""
    counts: dict[str, int] = {}
    for finding in findings:
        tax = finding.get("taxonomy") or classify(finding.get("rule", ""))
        code = tax.get("owasp_top10_2025") or "uncategorized"
        counts[code] = counts.get(code, 0) + 1
    return dict(sorted(counts.items()))

