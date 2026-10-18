from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engines.assumption_intelligence import AssumptionIntelligenceEngine
from .engines.experimental_validation import ExperimentalValidationEngine
from .engines.vulnerability_correlation import VulnerabilityCorrelationEngine
from .reporting import build_framework_report, write_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypto assumption-driven framework CLI")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd(), help="Repository root to analyze")
    parser.add_argument("--out", type=Path, default=Path("artifacts/framework_report.json"), help="Report output path")
    args = parser.parse_args()

    engine = AssumptionIntelligenceEngine(args.repo_root)
    assumptions = engine.extract_assumptions()
    hypotheses = engine.generate_hypotheses()
    experiments = ExperimentalValidationEngine().run(hypotheses, default_target=str(args.repo_root))
    correlations = VulnerabilityCorrelationEngine().correlate([
        {
            "target": str(args.repo_root),
            "hypothesis_id": item.hypothesis_id,
            "status": item.status,
        }
        for item in experiments
    ])

    report = build_framework_report(args.repo_root, assumptions, hypotheses, [
        {"hypothesis_id": item.hypothesis_id, "target": item.target, "status": item.status, "metrics": item.metrics}
        for item in experiments
    ], correlations)
    write_report(report, args.out)
    print(json.dumps({"assumption_count": len(assumptions), "hypothesis_count": len(hypotheses), "output": str(args.out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
