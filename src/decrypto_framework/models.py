from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


@dataclass
class Assumption:
    id: str = field(default_factory=lambda: str(uuid4()))
    area: str = "general"
    assumption: str = ""
    trust_boundary: str = "unknown"
    failure_mechanism: str = "unknown"
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass
class Hypothesis:
    id: str = field(default_factory=lambda: str(uuid4()))
    assumption_id: str = ""
    title: str = ""
    description: str = ""
    preconditions: list[str] = field(default_factory=list)
    expected_observable: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class Experiment:
    id: str = field(default_factory=lambda: str(uuid4()))
    hypothesis_id: str = ""
    name: str = ""
    controls: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)


@dataclass
class Observation:
    id: str = field(default_factory=lambda: str(uuid4()))
    hypothesis_id: str = ""
    target: str = ""
    status: str = "pending"
    evidence: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)


@dataclass
class CorrelatedFinding:
    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    target: str = ""
    observations: list[str] = field(default_factory=list)
    explanation: str = ""
    confidence: float = 0.0


@dataclass
class Report:
    generated_at: str = ""
    repository: str = ""
    assumptions: list[Assumption] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    correlations: list[CorrelatedFinding] = field(default_factory=list)
