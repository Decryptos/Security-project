from __future__ import annotations

from decrypto_framework.benchmark import build_default_benchmark_suite, evaluate_scenarios


def test_benchmark_suite_captures_unique_assumption_findings():
    suite = build_default_benchmark_suite()
    result = evaluate_scenarios(suite)

    assert result.total_scenarios == 3
    assert result.assumption_unique > result.conventional_unique
    assert result.summary
    assert all(item["name"] for item in result.scenarios)


def test_benchmark_suite_reports_unique_trust_boundary_findings():
    suite = build_default_benchmark_suite()
    result = evaluate_scenarios(suite)

    scenario = next(item for item in result.scenarios if item["name"] == "cors-cache boundary issue")
    assert "CORS-CACHE" in scenario["unique_assumption_findings"]
    assert "CORS-TRUST" in scenario["unique_assumption_findings"]


def test_benchmark_suite_has_metrics_for_comparison():
    suite = build_default_benchmark_suite()
    result = evaluate_scenarios(suite)

    assert 0.0 <= result.conventional_precision <= 1.0
    assert 0.0 <= result.assumption_precision <= 1.0
    assert 0.0 <= result.recall <= 1.0
