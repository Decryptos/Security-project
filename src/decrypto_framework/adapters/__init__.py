from __future__ import annotations


class SecurityProjectAuditorAdapter:
    """Adapter for the legacy root-level security project scanner."""

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def collect_metadata(self) -> dict:
        return {
            "component": "decrypto_assumption_scan.py",
            "status": "integrated",
            "focus": ["HTTP assumptions", "OpenAPI contract review", "authorized live testing"],
            "repo_root": self.repo_root,
        }

    def collect_findings(self) -> list[dict]:
        return [{"rule": "legacy-adapter", "status": "compatible", "target": self.repo_root}]
