from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExperimentResult:
    hypothesis_id: str
    target: str
    status: str = "pending"
    evidence: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)


class ExperimentalValidationEngine:
    """Run experiment scaffolding for hypothesis validation."""

    def __init__(self) -> None:
        self.results: list[ExperimentResult] = []

    def run(self, hypotheses: list[dict], default_target: str = "repository") -> list[ExperimentResult]:
        for hypothesis in hypotheses:
            result = ExperimentResult(
                hypothesis_id=hypothesis.get("assumption_id", hypothesis.get("title", "unknown")),
                target=default_target,
                status="validated" if hypothesis.get("confidence", 0) >= 0.6 else "pending",
                evidence={
                    "title": hypothesis.get("title", "unknown"),
                    "description": hypothesis.get("description", ""),
                    "controls": ["negative-control", "owner-validation"],
                },
                metrics={"confidence": float(hypothesis.get("confidence", 0.0))},
            )
            self.results.append(result)
        return self.results
