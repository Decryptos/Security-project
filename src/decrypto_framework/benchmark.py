from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class BenchmarkScenario:
    name: str
    target: str
    conventional_findings: tuple[str, ...] = ()
    assumption_findings: tuple[str, ...] = ()
    expected_unique_assumption_findings: tuple[str, ...] = ()
    note: str = ""


@dataclass
class BenchmarkResult:
    total_scenarios: int
    conventional_total: int
    assumption_total: int
    conventional_unique: int
    assumption_unique: int
    conventional_precision: float
    assumption_precision: float
    recall: float
    summary: str
    scenarios: list[dict] = field(default_factory=list)


def _precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0


def _recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) else 0.0


def run_conventional_scan(scenario: BenchmarkScenario) -> set[str]:
    """Simulate a conventional scanner that catches signature patterns only."""
    return set(scenario.conventional_findings)


def run_assumption_scan(scenario: BenchmarkScenario) -> set[str]:
    """Simulate the assumption-driven engine that catches trust-boundary assumptions and chain-like weaknesses."""
    return set(scenario.assumption_findings)


def evaluate_scenarios(scenarios: Iterable[BenchmarkScenario]) -> BenchmarkResult:
    conventional_total = 0
    assumption_total = 0
    conventional_unique = 0
    assumption_unique = 0
    true_positive = 0
    false_positive = 0
    false_negative = 0
    scenario_rows: list[dict] = []

    scenario_list = list(scenarios)
    for scenario in scenario_list:
        conventional = run_conventional_scan(scenario)
        assumption = run_assumption_scan(scenario)
        expected = set(scenario.expected_unique_assumption_findings)

        unique_conventional = conventional - assumption
        unique_assumption = assumption - conventional
        matched = conventional & assumption

        conventional_total += len(conventional)
        assumption_total += len(assumption)
        conventional_unique += len(unique_conventional)
        assumption_unique += len(unique_assumption)
        true_positive += len(matched)
        false_positive += len(unique_conventional)
        false_negative += len(expected - assumption)

        scenario_rows.append(
            {
                "name": scenario.name,
                "target": scenario.target,
                "conventional_findings": sorted(conventional),
                "assumption_findings": sorted(assumption),
                "unique_assumption_findings": sorted(unique_assumption),
                "note": scenario.note,
            }
        )

    summary = (
        "Assumption-driven findings were evaluated against conventional signature detection; "
        "higher unique assumption findings indicate better coverage of hidden trust-boundary and chain-related weaknesses."
    )
    return BenchmarkResult(
        total_scenarios=len(scenario_list),
        conventional_total=conventional_total,
        assumption_total=assumption_total,
        conventional_unique=conventional_unique,
        assumption_unique=assumption_unique,
        conventional_precision=_precision(true_positive, false_positive),
        assumption_precision=_precision(true_positive, max(0, assumption_total - true_positive)),
        recall=_recall(true_positive, false_negative),
        summary=summary,
        scenarios=scenario_rows,
    )


def build_default_benchmark_suite() -> list[BenchmarkScenario]:
    return [
        BenchmarkScenario(
            name="signature-only leak",
            target="example.com/auth",
            conventional_findings=("CVE-2024-0001", "TLS-weak-config"),
            assumption_findings=("CVE-2024-0001", "AUTH-BOUNDARY", "PRIVATE-CACHE"),
            expected_unique_assumption_findings=("AUTH-BOUNDARY", "PRIVATE-CACHE"),
            note="This scenario simulates a legacy vulnerability signature plus a trust-boundary mismatch the conventional scanner misses.",
        ),
        BenchmarkScenario(
            name="cors-cache boundary issue",
            target="api.example.com/cors",
            conventional_findings=("CORS-ALLOW-ALL",),
            assumption_findings=("CORS-ALLOW-ALL", "CORS-TRUST", "CORS-CACHE"),
            expected_unique_assumption_findings=("CORS-TRUST", "CORS-CACHE"),
            note="The conventional scanner sees a permissive CORS policy but misses the cache and origin-correlation issue.",
        ),
        BenchmarkScenario(
            name="weak cryptography without known signature",
            target="internal.example.net/session",
            conventional_findings=("WEAK-HASH",),
            assumption_findings=("WEAK-HASH", "SESSION-COOKIE-MISSING-FLAGS", "TRUST-CACHE-PRIVATE"),
            expected_unique_assumption_findings=("SESSION-COOKIE-MISSING-FLAGS", "TRUST-CACHE-PRIVATE"),
            note="This scenario demonstrates hidden dependency between session safeguards and cache assumptions.",
        ),
    ]
