from __future__ import annotations

from pathlib import Path

from decrypto_framework import AssumptionIntelligenceEngine, ExperimentalValidationEngine, VulnerabilityCorrelationEngine, build_framework_report


def test_assumption_engine_extracts_security_domains(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import secrets\n\n" 
        "def login(token):\n    return token\n\n" 
        "def make_cookie():\n    return 'sessionid=abc'\n",
        encoding="utf-8",
    )
    (repo / "config.yaml").write_text("jwt: token\n", encoding="utf-8")

    assumptions = AssumptionIntelligenceEngine(repo).extract_assumptions()
    assert assumptions
    assert any(item["area"] == "authentication" for item in assumptions)


def test_validation_engine_generates_observations():
    hypotheses = [{"assumption_id": "auth", "title": "Auth boundary", "description": "Auth boundary is assumed valid", "confidence": 0.8}]
    observations = ExperimentalValidationEngine().run(hypotheses, default_target="example.com")
    assert observations[0].status == "validated"


def test_correlation_engine_combines_multiple_observations():
    observations = [
        {"target": "example.com", "hypothesis_id": "auth"},
        {"target": "example.com", "hypothesis_id": "cache"},
    ]
    correlations = VulnerabilityCorrelationEngine().correlate(observations)
    assert correlations
    assert correlations[0]["target"] == "example.com"


def test_report_builder_has_summary_fields():
    report = build_framework_report(
        Path("/tmp/repo"),
        [{"area": "authentication"}],
        [{"title": "Auth hypothesis"}],
        [{"status": "validated"}],
        [{"title": "Correlated risk"}],
    )
    assert report["assumption_count"] == 1
    assert report["hypothesis_count"] == 1
    assert report["correlation_count"] == 1
