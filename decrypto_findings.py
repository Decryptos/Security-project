"""Shared finding-record factory for Decrypto's scanners.

Kept in its own module — depending only on `decrypto_taxonomy` — so both
`decrypto_assumption_scan.py` (passive/observational checks) and
`decrypto_active_checks.py` (opt-in active payload checks) can import
`new_finding` at module load time without a circular import.
"""
from __future__ import annotations

import hashlib
from typing import Any

from decrypto_taxonomy import classify


def new_finding(rule: str, url: str, title: str, assumption: str,
                evidence: dict[str, Any], reasoning: str, fix: str, verification: str,
                priority: str = "review", exploitability: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a finding.

    `exploitability`, when provided, states — in a conservative, falsifiable way —
    whether the *observed response data alone* (never an attack payload) already
    confirms the mechanism, or whether further owner-authorized testing is still
    required before any impact claim. It never upgrades `status`, which always
    stays UNCONFIRMED until the owner validates real-world impact.
    """
    finding = {
        "id": hashlib.sha256((rule + "|" + url).encode()).hexdigest()[:10].upper(),
        "rule": rule,
        "target": url,
        "title": title,
        "priority": priority,
        "status": "UNCONFIRMED — needs owner validation",
        "evidence_class": "observable_configuration_or_contract",
        "assumption_tested": assumption,
        "evidence": evidence,
        "how_model_found_it": reasoning,
        "remediation": fix,
        "validation_needed": verification,
        "taxonomy": classify(rule),
    }
    if exploitability is not None:
        finding["exploitability"] = exploitability
    return finding
