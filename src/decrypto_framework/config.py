from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    repo_root: Path = Path.cwd()
    allow_external_testing: bool = False
    local_only: bool = True
    strict_validation: bool = True
    report_dir: Path = Path("artifacts")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls()
