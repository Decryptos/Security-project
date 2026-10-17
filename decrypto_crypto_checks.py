"""
Optimized static crypto-implementation checks for Decrypto.

Goals:
- Python-first scanning with tighter heuristics to reduce false positives.
- CWE-aware findings and confidence scoring.
- Repo ignore/allowlist support via .decrypto-ignore.
- Redacted evidence and minimal CLI for local use.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, List

# CWE mapping (kept minimal and deterministic)
CWE_RULES = {
    "CRYPTO-HARDKEY": ("CWE-321", "Use of Hard-coded Cryptographic Key"),
    "CRYPTO-PEM-IN-CODE": ("CWE-321", "Use of Hard-coded Cryptographic Key"),
    "CRYPTO-WEAK-HASH": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "CRYPTO-WEAK-CIPHER": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "CRYPTO-INSECURE-RNG": ("CWE-330", "Use of Insufficiently Random Values"),
    "CRYPTO-TLS-WORKAROUND": ("CWE-295", "Improper Certificate Validation"),
    "CRYPTO-PBKDF2": ("CWE-916", "Use of Password Hash With Insufficient Computational Effort"),
    "CRYPTO-POTENTIALLY-ROLLING": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
}

# Default locations to ignore (common vendored or virtualenv dirs)
DEFAULT_IGNORES = {"node_modules", "vendor", ".venv", "venv", "__pycache__", ".git"}

# Heuristics (more conservative than a raw regex scan)
_PATTERNS = [
    # Hardcoded-looking key assigned to a variable (hex/base64), require assignment to reduce noise
    (re.compile(r"\b\w+\s*=\s*['\"]([0-9a-f]{32,}|[A-Za-z0-9+/]{32,}={0,2})['\"]"), "CRYPTO-HARDKEY", "Possible hardcoded key or secret literal"),

    # PEM private keys in files
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "CRYPTO-PEM-IN-CODE", "Private key PEM embedded in repository"),

    # Weak hashes referenced
    (re.compile(r"\b(md5|sha1|md4)\b", re.I), "CRYPTO-WEAK-HASH", "Use of deprecated or weak hash algorithm"),

    # Insecure RNG usage in Python
    (re.compile(r"\brandom\.(random|seed)\s*\(|\bos\.urandom\s*\(|\bMath\.random\(|\bseedrandom\b"), "CRYPTO-INSECURE-RNG", "Use of non-cryptographic RNG or explicit seeding"),

    # Disabling TLS certificate validation
    (re.compile(r"\bverify\s*=\s*False\b|_create_unverified_context|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED", re.I), "CRYPTO-TLS-WORKAROUND", "TLS certificate validation disabled or bypassed"),

    # PBKDF2 usage
    (re.compile(r"pbkdf2|pbkdf2_hmac", re.I), "CRYPTO-PBKDF2", "PBKDF2 use detected — verify iterations and salt usage"),

    # Low-level cipher APIs (may indicate custom crypto)
    (re.compile(r"\b(createCipher|crypto\.createCipher|CryptoJS|Cipher\()"), "CRYPTO-POTENTIALLY-ROLLING", "Potential use of low-level cipher APIs; ensure authenticated encryption and correct IV/nonce usage"),
]


def _id_for(rule: str, file_path: str, line: int) -> str:
    return hashlib.sha256(f"{rule}|{file_path}|{line}".encode()).hexdigest()[:12].upper()


def _load_allowlist(root: Path) -> List[str]:
    allowlist = []
    f = root / ".decrypto-ignore"
    if not f.exists():
        return allowlist
    try:
        for ln in f.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            allowlist.append(ln)
    except Exception:
        pass
    return allowlist


def _is_ignored(path: Path, root: Path, allowlist: Iterable[str]) -> bool:
    # Ignore by directory name
    for part in path.parts:
        if part in DEFAULT_IGNORES:
            return True
    # Check allowlist/glob: if any allowlist pattern matches, ignore (patterns are relative globs)
    rel = str(path.relative_to(root))
    for pat in allowlist:
        if Path(root / pat).match(rel) or Path(rel).match(pat):
            return True
    return False


def _redact_excerpt(snippet: str) -> str:
    # Replace long alnum/base64-like sequences with <REDACTED>
    return re.sub(r"[A-Za-z0-9+/=]{8,}", "<REDACTED>", snippet)


def scan_repo_for_crypto_issues(root: Path, languages: List[str] | None = None) -> dict[str, Any]:
    if languages is None:
        languages = ["python"]

    findings: List[dict[str, Any]] = []
    inspected = 0
    allowlist = _load_allowlist(root)

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _is_ignored(path, root, allowlist):
            continue
        # simple language filter
        if path.suffix == ".py":
            lang = "python"
        elif path.suffix in {".js", ".mjs", ".cjs"}:
            lang = "javascript"
        else:
            continue
        if lang not in languages:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            # skip unreadable files
            continue
        inspected += 1

        # Avoid scanning very small files for false positives
        if len(text) < 16:
            continue

        for pattern, rule, title in _PATTERNS:
            for m in pattern.finditer(text):
                start = max(0, m.start() - 60)
                end = min(len(text), m.end() + 60)
                snippet = text[start:end]
                excerpt = _redact_excerpt(snippet)[:300]
                line = text.count("\n", 0, m.start()) + 1
                confidence = "medium"

                # If rule is PBKDF2 try to detect iteration count nearby and adjust confidence
                remediation = None
                if rule == "CRYPTO-PBKDF2":
                    # Look for a nearby integer that could be iterations
                    window = text[max(0, m.start() - 200):m.end() + 200]
                    it = re.search(r"\b(\d{3,7})\b", window)
                    if it:
                        try:
                            iterations = int(it.group(1))
                            if iterations < 100_000:
                                confidence = "high"
                                remediation = f"Detected PBKDF2 with low iterations ({iterations}). Recommend >=100000 iterations."
                            else:
                                confidence = "low"
                        except Exception:
                            pass
                    else:
                        confidence = "medium"

                cwe_id, cwe_title = CWE_RULES.get(rule, ("CWE-693", "Protection Mechanism Failure"))
                evidence = {"file": str(path.relative_to(root)), "line": line, "match_excerpt": excerpt}
                finding = {
                    "id": _id_for(rule, str(path.relative_to(root)), line),
                    "rule": rule,
                    "title": title,
                    "priority": "review",
                    "status": "UNCONFIRMED — needs owner validation",
                    "evidence_class": "static_code_finding",
                    "evidence": evidence,
                    "remediation": remediation or "Review and fix the highlighted usage.",
                    "cwe": {"id": cwe_id, "title": cwe_title},
                    "confidence": confidence,
                }
                findings.append(finding)

    meta = {"files_inspected": inspected, "languages": languages, "finding_count": len(findings)}
    return {"findings": findings, "meta": meta}


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Decrypto static crypto checks (optimized)")
    p.add_argument("root", nargs="?", default=".")
    p.add_argument("--history", action="store_true", help="(opt-in) placeholder for git-history review")
    args = p.parse_args()
    out = scan_repo_for_crypto_issues(Path(args.root))
    if args.history:
        out["history_scan"] = [{"note": "History scan is opt-in and runs separately."}]
    print(json.dumps(out, indent=2))
