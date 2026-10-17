"""
Static crypto-implementation checks for Decrypto.

This module scans a repository snapshot (files under a given root) for common
crypto implementation anti-patterns and insecure usages in Python and JavaScript
source files. It is intentionally conservative and reports leads for manual
review, not confirmed vulnerabilities.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

# Reuse the new_finding factory shape from the main scanner by reconstructing a
# compatible minimal function here. The main module will merge findings.

def _id_for(rule: str, target: str) -> str:
    return hashlib.sha256((rule + "|" + target).encode()).hexdigest()[:10].upper()


def _make_finding(rule: str, target: str, title: str, evidence: dict[str, Any], priority: str = "review") -> dict[str, Any]:
    return {
        "id": _id_for(rule, target),
        "rule": rule,
        "target": target,
        "title": title,
        "priority": priority,
        "status": "UNCONFIRMED — needs owner validation",
        "evidence_class": "static_code_finding",
        "evidence": evidence,
        "remediation": evidence.get("remediation", "Review and fix the highlighted usage."),
    }


# Patterns to flag. These are heuristics and must be reviewed manually.
_PATTERNS = [
    # Hardcoded-looking long hex or base64 strings (possible keys/secrets)
    (r"(?i)\b([0-9a-f]{32,}|[A-Za-z0-9+/]{32,}={0,2})\b", "CRYPTO-HARDKEY", "Possible hardcoded key or secret literal"),

    # PEM private keys in files
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "CRYPTO-PEM-IN-CODE", "Private key PEM embedded in repository"),

    # Weak hashes
    (r"\b(md5|sha1|md4)\b", "CRYPTO-WEAK-HASH", "Use of deprecated or weak hash algorithm"),

    # Insecure ciphers/modes
    (r"\b(aes-?ecb|des|rc4|3des|tripledes)\b", "CRYPTO-WEAK-CIPHER", "Use of weak cipher or insecure mode (ECB/RC4/DES)"),

    # Insecure RNG usage in Python or JS
    (r"\brandom\.random\(|\brandom\.seed\(|\bMath\.random\(|\bseedrandom\b", "CRYPTO-INSECURE-RNG", "Use of non-cryptographic RNG or explicit seeding"),

    # Disabling TLS certificate validation
    (r"\bverify\s*=\s*False\b|_create_unverified_context|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED", "CRYPTO-TLS-WORKAROUND", "TLS certificate validation disabled or bypassed"),

    # Weak PBKDF2 iterations (heuristic: small iteration numbers near pbkdf2 calls)
    (r"(?i)pbkdf2\b", "CRYPTO-PBKDF2", "PBKDF2 use detected — verify iterations and salt usage"),

    # Rolling-your-own crypto (use of low-level primitives without AE)
    (r"\b(createCipher\b|Cipher\(|crypto\.createCipher|CryptoJS)", "CRYPTO-POTENTIALLY-ROLLING", "Potential use of low-level cipher APIs; ensure authenticated encryption and correct IV/nonce usage"),
]


def _file_language(path: Path) -> str | None:
    if path.suffix == ".py":
        return "python"
    if path.suffix in (".js", ".mjs", ".cjs"):
        return "javascript"
    return None


def scan_repo_for_crypto_issues(root: Path, languages: list[str] | None = None) -> dict[str, Any]:
    """Scan files under `root` for crypto anti-patterns.

    Returns a dict with findings and a little metadata.
    """
    if languages is None:
        languages = ["python", "javascript"]

    findings: list[dict[str, Any]] = []
    inspected = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        lang = _file_language(path)
        if lang is None or lang not in languages:
            continue
        # Skip large binary files
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        inspected += 1
        for pat, rule, title in _PATTERNS:
            for m in re.finditer(pat, text):
                snippet = text[max(0, m.start() - 40):min(len(text), m.end() + 40)]
                # Do not include long secrets in evidence; only include a redacted excerpt
                excerpt = re.sub(r"[A-Za-z0-9+/=]{8,}", "<REDACTED>", snippet)
                evidence = {
                    "file": str(path.relative_to(root)),
                    "line": text.count("\n", 0, m.start()) + 1,
                    "match_excerpt": excerpt[:200],
                }
                findings.append(_make_finding(rule, evidence["file"], title, evidence))

    meta = {"files_inspected": inspected, "languages": languages, "finding_count": len(findings)}
    return {"findings": findings, "meta": meta}


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser()
    p.add_argument("root", nargs="?", default=Path.cwd())
    args = p.parse_args()
    res = scan_repo_for_crypto_issues(Path(args.root))
    print(json.dumps(res, indent=2))
