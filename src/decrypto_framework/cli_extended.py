from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engines.assumption_intelligence import AssumptionIntelligenceEngine
from .engines.experimental_validation import ExperimentalValidationEngine
from .engines.vulnerability_correlation import VulnerabilityCorrelationEngine
from .engines.exploitability import ExploitabilityVerificationEngine
from .reporting import build_framework_report, write_report
from .evidence import write_evidence_bundle


def _confirm_interactive() -> bool:
    try:
        resp = input("Proceed with exploitability verification? This must be run only on machines you control. (yes/no): ")
    except EOFError:
        return False
    return resp.strip().lower() in ("y", "yes")


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypto assumption-driven framework CLI (extended)")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd(), help="Repository root to analyze")
    parser.add_argument("--out", type=Path, default=Path("artifacts/framework_report.json"), help="Report output path")

    # exploitability options
    parser.add_argument("--exploit-verify", action="store_true", help="Run exploitability verification flow (gated)")
    parser.add_argument("--auth-manifest", type=Path, help="Path to owner authorization manifest (required for exploit-verify)")
    parser.add_argument("--allow-external", action="store_true", help="Allow external target verification when manifest permits (must run locally)")

    args = parser.parse_args()

    engine = AssumptionIntelligenceEngine(args.repo_root)
    assumptions = engine.extract_assumptions()
    hypotheses = engine.generate_hypotheses()
    experiments = ExperimentalValidationEngine().run(hypotheses, default_target=str(args.repo_root))
    observations = [
        {"hypothesis_id": item.hypothesis_id, "target": item.target, "status": item.status, "metrics": item.metrics}
        for item in experiments
    ]
    correlations = VulnerabilityCorrelationEngine().correlate(observations)

    # Prepare base report
    report = build_framework_report(args.repo_root, assumptions, hypotheses, observations, correlations)

    # If exploit verification requested
    if args.exploit_verify:
        if not args.auth_manifest:
            print("--auth-manifest is required when --exploit-verify is used", file=sys.stderr)
            return 2

        # Simple interactive pre-flight gate
        print("Exploitability verification requested. This flow is gated: ensure you have owner authorization and are running locally.")
        if not _confirm_interactive():
            print("Interactive confirmation not provided. Aborting exploit verification.")
            report["exploit_verification"] = {"status": "aborted_interactive"}
            write_report(report, args.out)
            return 3

        # For now we pick the first hypothesis target if available; otherwise require manifest target
        target = None
        if observations:
            target = observations[0].get("target")
        # Call exploitability engine
        ev = ExploitabilityVerificationEngine()
        result = ev.run(
            hypothesis_id=hypotheses[0]["assumption_id"] if hypotheses else "manual",
            target=target or "",
            manifest_path=args.auth_manifest,
            require_approval=True,
        )
        report["exploit_verification"] = result
        # write evidence bundle
        bundle_path = write_evidence_bundle(result, base_dir=Path("artifacts/verification"))
        print(json.dumps({"exploit_result": result["status"], "evidence": str(bundle_path)}))

    write_report(report, args.out)
    print(json.dumps({"assumption_count": len(assumptions), "hypothesis_count": len(hypotheses), "output": str(args.out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
