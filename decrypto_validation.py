"""Paired, non-exploitative CORS policy verification for authorized endpoints.

Two credential-free observations can demonstrate policy reflection, but cannot
prove cross-user disclosure, authenticated browser access, or exploitability.
"""
from __future__ import annotations

import hashlib
from typing import Any

ORIGINS = ("https://audit-origin.invalid", "https://second-audit-origin.invalid")


def evaluate_cors_pair(url: str, samples: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare two fixed test Origin values using only sanitized header metadata."""
    by_origin = {sample["origin"]: sample for sample in samples}
    valid = len(samples) == 2 and all(origin in by_origin for origin in ORIGINS)
    reflected = valid and all(
        by_origin[origin]["allow_origin"] == origin
        and by_origin[origin]["allow_credentials"] == "true"
        for origin in ORIGINS
    )
    return {
        "id": hashlib.sha256(("CORS-PAIRED|" + url).encode()).hexdigest()[:10].upper(),
        "rule": "CORS-PAIRED",
        "target": url,
        "title": "Paired origin-policy observation",
        "status": "UNCONFIRMED — impact and exploitability not demonstrated",
        "evidence_class": "paired_header_observation",
        "evidence": {
            "sample_count": len(samples),
            "complete": bool(valid),
            "both_untrusted_origins_reflected_with_credentials": bool(reflected),
            "statuses": [sample["status"] for sample in samples],
        },
        "assumption_tested": "Untrusted origins should not be credential-authorized by a dynamic allow-origin policy.",
        "validation_needed": "Use an owner-controlled test account and non-sensitive test resource to validate browser behavior and actual data exposure separately.",
    }


def metadata(origin: str, status: int, headers: Any) -> dict[str, Any]:
    """Retain only defined metadata, never response bodies or arbitrary headers."""
    return {
        "origin": origin,
        "status": status,
        "allow_origin": ((headers.get("Access-Control-Allow-Origin") or "").strip() if len(headers.get_all("Access-Control-Allow-Origin", [])) == 1 else ""),
        "allow_credentials": ((headers.get("Access-Control-Allow-Credentials") or "").strip() if len(headers.get_all("Access-Control-Allow-Credentials", [])) == 1 else ""),
    }
