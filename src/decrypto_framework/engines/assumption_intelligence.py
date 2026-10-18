from __future__ import annotations

from pathlib import Path
from typing import Any

from decrypto_framework.adapters.security_project_auditor import SecurityProjectAuditorAdapter
from decrypto_framework.logging_utils import get_logger


class AssumptionIntelligenceEngine:
    """Extract security assumptions and generate testable hypotheses for the repository."""

    ASSUMPTION_KEYWORDS = {
        "authentication": ["auth", "jwt", "session", "token", "login", "oauth", "authorization"],
        "cryptography": ["crypto", "cipher", "hash", "hmac", "tls", "ssl", "pem", "pbkdf2"],
        "trust_boundary": ["cors", "origin", "same-site", "cache", "cdn", "proxy"],
        "randomness": ["random", "secrets", "entropy", "nonce"],
        "deployment": ["https", "helmet", "security", "strict-transport"],
    }

    def __init__(self, repo_root: str | Path):
        self.repo_root = Path(repo_root)
        self.logger = get_logger("decrypto.assumption")
        self._legacy_adapter = SecurityProjectAuditorAdapter(str(self.repo_root))

    def extract_assumptions(self) -> list[dict[str, Any]]:
        assumptions: list[dict[str, Any]] = []

        for path in self.repo_root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".py", ".js", ".json", ".md", ".yml", ".yaml"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except Exception:
                continue

            for area, keywords in self.ASSUMPTION_KEYWORDS.items():
                hits = sorted(set(keyword for keyword in keywords if keyword.lower() in text.lower()))
                if not hits:
                    continue
                assumptions.append(
                    {
                        "area": area,
                        "assumption": f"The repository assumes {area} controls remain valid across code and configuration boundaries.",
                        "trust_boundary": area,
                        "failure_mechanism": "implementation or policy drift across trust boundaries",
                        "evidence": {"path": str(path.relative_to(self.repo_root)), "keywords": hits},
                        "confidence": min(0.95, 0.45 + 0.1 * len(hits)),
                    }
                )

        if not assumptions:
            assumptions.append(
                {
                    "area": "repository",
                    "assumption": "The repository assumes secure defaults remain consistent across all components and execution paths.",
                    "trust_boundary": "unknown",
                    "failure_mechanism": "implicit trust or stale assumptions",
                    "evidence": {"path": "repository", "keywords": ["security", "assumption", "trust"]},
                    "confidence": 0.35,
                }
            )

        return assumptions

    def generate_hypotheses(self) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []
        for assumption in self.extract_assumptions():
            hypotheses.append(
                {
                    "assumption_id": assumption.get("area", "repository"),
                    "title": f"{assumption['area']}: {assumption['assumption']}",
                    "description": assumption["assumption"],
                    "preconditions": [
                        "The relevant trust boundary is not enforced consistently",
                        "Inputs or runtime state can cross an implicit security boundary",
                    ],
                    "expected_observable": [
                        "Unexpected behavior under non-standard inputs",
                        "Evidence of drift between policy and implementation",
                    ],
                    "confidence": assumption.get("confidence", 0.0),
                }
            )
        return hypotheses

    def legacy_summary(self) -> dict[str, Any]:
        """Provide a compatibility summary for the existing scanner modules."""
        return {
            "legacy_auditor": self._legacy_adapter.collect_metadata(),
            "static_crypto": self._legacy_adapter.collect_static_findings(),
        }
