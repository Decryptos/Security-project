"""
Static crypto-implementation checks for Decrypto.

This module scans a repository snapshot (files under a given root) for common
crypto implementation anti-patterns and insecure usages in Python and JavaScript
source files. It is intentionally conservative and reports leads for manual
review, not confirmed vulnerabilities.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from decrypto_taxonomy import classify, summarize
from decrypto_nonce_checks import check_python_aead_nonces

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
        "taxonomy": classify(rule),
        "evidence": evidence,
        "remediation": evidence.get("remediation", "Review and fix the highlighted usage."),
    }


# Patterns to flag. These are heuristics and must be reviewed manually.
# Compile once at import time so each repository scan reuses the same regex objects
# rather than recompiling them for every file and every rule.
_PATTERNS = [
    # Hardcoded-looking long hex or base64 strings (possible keys/secrets)
    (re.compile(r"(?i)\b([0-9a-f]{32,}|[A-Za-z0-9+/]{32,}={0,2})\b"), "CRYPTO-HARDKEY", "Possible hardcoded key or secret literal"),

    # PEM private keys in files
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "CRYPTO-PEM-IN-CODE", "Private key PEM embedded in repository"),

    # Weak hashes
    (re.compile(r"(?i)\b(md5|sha-?1|md4)\b"), "CRYPTO-WEAK-HASH", "Use of deprecated or weak hash algorithm"),

    # Insecure ciphers/modes
    (re.compile(r"(?i)\b(aes-?ecb|des|rc4|3des|tripledes)\b"), "CRYPTO-WEAK-CIPHER", "Use of weak cipher or insecure mode (ECB/RC4/DES)"),

    # Insecure RNG usage in Python or JS
    (re.compile(r"\brandom\.random\(|\brandom\.seed\(|\bMath\.random\(|\bseedrandom\b"), "CRYPTO-INSECURE-RNG", "Use of non-cryptographic RNG or explicit seeding"),

    # Disabling TLS certificate validation
    (re.compile(r"\bverify\s*=\s*False\b|_create_unverified_context|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"), "CRYPTO-TLS-WORKAROUND", "TLS certificate validation disabled or bypassed"),

    # Weak PBKDF2 iterations (heuristic: small iteration numbers near pbkdf2 calls)
    (re.compile(r"(?i)pbkdf2\b"), "CRYPTO-PBKDF2", "PBKDF2 use detected — verify iterations and salt usage"),

    # Rolling-your-own crypto (use of low-level primitives without AE)
    (re.compile(r"\b(createCipher\b|Cipher\(|crypto\.createCipher|CryptoJS)"), "CRYPTO-POTENTIALLY-ROLLING", "Potential use of low-level cipher APIs; ensure authenticated encryption and correct IV/nonce usage"),

    # Variants: block-mode, protocol, key-size, KDF cost, JWT and static IV issues
    (re.compile(r"\bMODE_ECB\b|(?i:createCipheriv\(\s*['\"][a-z0-9-]*ecb)"), "CRYPTO-ECB-MODE", "ECB block mode selected explicitly"),
    (re.compile(r"\bPROTOCOL_(?:SSLv2|SSLv3|SSLv23|TLSv1|TLSv1_1)\b|secureProtocol\s*:\s*['\"](?:SSLv3|TLSv1)"), "CRYPTO-TLS-OLD-PROTOCOL", "Deprecated SSL/TLS protocol version selected"),
    (re.compile(r"\bcheck_hostname\s*=\s*False\b|\bCERT_NONE\b"), "CRYPTO-TLS-WORKAROUND", "TLS certificate validation disabled or bypassed"),
    (re.compile(r"(?:key_size\s*=\s*|modulusLength\s*:\s*)(?:512|768|1024)\b"), "CRYPTO-SMALL-RSA-KEY", "RSA key size below 2048 bits"),
    (re.compile(r"(?i)iterations\s*=\s*[1-9]\d{0,4}\b(?!\d)"), "CRYPTO-WEAK-KDF-ITERATIONS", "Password KDF iteration count below 100000"),
    (re.compile(r"(?i)[\"']alg[\"']\s*:\s*[\"']none[\"']|algorithms\s*=\s*\[\s*[\"']none[\"']"), "CRYPTO-JWT-NONE-ALG", "JWT 'none' algorithm accepted or issued"),
    (re.compile(r"(?i)\b(?:iv|nonce)\s*=\s*b?[\"'][^\"']{8,}[\"']"), "CRYPTO-STATIC-IV", "Hardcoded IV or nonce literal"),
]


def _scan_text(path: Path, root: Path, text: str) -> list[dict[str, Any]]:
    """Scan a file once against the compiled regex list and collect findings."""
    findings: list[dict[str, Any]] = []
    relative_path = str(path.relative_to(root))
    source_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    # Precompute newline offsets so each match's line number is a binary search, not a rescan.
    newlines = [i for i, ch in enumerate(text) if ch == "\n"]
    for pattern, rule, title in _PATTERNS:
        for m in pattern.finditer(text):
            evidence = {
                "file": relative_path,
                "line": bisect.bisect_left(newlines, m.start()) + 1,
                "column": m.start() - text.rfind("\n", 0, m.start()),
                "source_sha256": source_sha256,
            }
            findings.append(_make_finding(
                rule,
                f'{evidence["file"]}:{evidence["line"]}:{evidence["column"]}',
                title,
                evidence,
            ))
    return findings


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
    skipped: list[dict[str, str]] = []

    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Source root must be a directory")
    excluded_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__"}

    def walk_error(error: OSError) -> None:
        path = Path(error.filename) if error.filename else root
        skipped.append({"file": str(path.relative_to(root)), "reason": "Directory could not be read"})

    for directory, folders, files in os.walk(root, followlinks=False, onerror=walk_error):
        kept = []
        for folder in sorted(folders):
            path = Path(directory) / folder
            if folder in excluded_dirs:
                continue
            if path.is_symlink():
                skipped.append({"file": str(path.relative_to(root)), "reason": "Linked directory skipped"})
                continue
            kept.append(folder)
        folders[:] = kept
        for filename in sorted(files):
            path = Path(directory) / filename
            lang = _file_language(path)
            if lang is None or lang not in languages:
                continue
            relative = str(path.relative_to(root))
            try:
                if path.is_symlink() or not path.is_file():
                    skipped.append({"file": relative, "reason": "Link or non-regular file skipped"})
                    continue
                # Bound the actual read, even if a file grows after metadata checks.
                with path.open("rb") as stream:
                    raw = stream.read(1_048_577)
                if len(raw) > 1_048_576:
                    skipped.append({"file": relative, "reason": "File exceeds 1 MiB"})
                    continue
                text = raw.decode("utf-8")
            except (OSError, UnicodeError):
                skipped.append({"file": relative, "reason": "File could not be read as UTF-8"})
                continue
            inspected += 1
            file_findings = _scan_text(path, root, text)
            if lang == "python":
                file_findings.extend(check_python_aead_nonces(text, relative))
            # Hash the exact input bytes; do not normalize line endings.
            source_hash = hashlib.sha256(raw).hexdigest()
            for finding in file_findings:
                finding["evidence"]["source_sha256"] = source_hash
            findings.extend(file_findings)

    meta = {"files_inspected": inspected, "languages": languages, "finding_count": len(findings),
            "skipped": skipped, "excluded_directories": sorted(excluded_dirs)}

    return {"findings": findings, "meta": meta, "findings_by_category": summarize(findings)}


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser()
    p.add_argument("root", nargs="?", default=Path.cwd())
    args = p.parse_args()
    res = scan_repo_for_crypto_issues(Path(args.root))
    print(json.dumps(res, indent=2))

