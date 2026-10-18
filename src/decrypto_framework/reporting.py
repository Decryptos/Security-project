from __future__ import annotations

import json
from pathlib import Path


def build_framework_report(repo_root: str | Path, assumptions: list[dict], hypotheses: list[dict], observations: list[dict], correlations: list[dict]) -> dict:
    return {
        "repository": str(repo_root),
        "version": "0.1.0",
        "assumption_count": len(assumptions),
        "hypothesis_count": len(hypotheses),
        "observation_count": len(observations),
        "correlation_count": len(correlations),
        "assumptions": assumptions,
        "hypotheses": hypotheses,
        "observations": observations,
        "correlations": correlations,
        "notable_constraints": [
            "No unauthorized testing",
            "Keep proprietary methodology local",
            "Do not fabricate vulnerabilities",
        ],
    }


def write_report(report: dict, output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return output
