from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from .benchmark import build_default_benchmark_suite, evaluate_scenarios, BenchmarkScenario, BenchmarkResult


def _load_suite(path: Path) -> list[BenchmarkScenario]:
    data = json.loads(path.read_text(encoding="utf-8"))
    scenarios: list[BenchmarkScenario] = []
    for item in data:
        scenarios.append(BenchmarkScenario(**item))
    return scenarios


def _write_json(result: BenchmarkResult, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    # Convert dataclasses to serializable dict
    j = {
        "total_scenarios": result.total_scenarios,
        "conventional_total": result.conventional_total,
        "assumption_total": result.assumption_total,
        "conventional_unique": result.conventional_unique,
        "assumption_unique": result.assumption_unique,
        "conventional_precision": result.conventional_precision,
        "assumption_precision": result.assumption_precision,
        "recall": result.recall,
        "summary": result.summary,
        "scenarios": result.scenarios,
    }
    out.write_text(json.dumps(j, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_markdown(result: BenchmarkResult, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Decrypto Benchmark Summary",
        "",
        f"Total scenarios: {result.total_scenarios}",
        f"Conventional findings (total): {result.conventional_total}",
        f"Assumption-driven findings (total): {result.assumption_total}",
        f"Unique conventional findings: {result.conventional_unique}",
        f"Unique assumption findings: {result.assumption_unique}",
        f"Conventional precision: {result.conventional_precision:.2f}",
        f"Assumption precision: {result.assumption_precision:.2f}",
        f"Recall (matched vs expected): {result.recall:.2f}",
        "",
        "## Scenario details",
        "",
    ]
    for s in result.scenarios:
        lines += [
            f"### {s['name']}",
            f"Target: {s['target']}",
            f"Conventional findings: {', '.join(s['conventional_findings']) or 'None'}",
            f"Assumption-driven findings: {', '.join(s['assumption_findings']) or 'None'}",
            f"Unique assumption findings: {', '.join(s['unique_assumption_findings']) or 'None'}",
            "",
        ]
    out.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Decrypto benchmark suite and export results")
    parser.add_argument("--suite", type=Path, help="Optional JSON file describing benchmark scenarios")
    parser.add_argument("--out-json", type=Path, default=Path("artifacts/benchmarks/result.json"), help="JSON output path")
    parser.add_argument("--out-md", type=Path, default=Path("artifacts/benchmarks/result.md"), help="Markdown output path")
    args = parser.parse_args(argv)

    if args.suite:
        scenarios = _load_suite(args.suite)
    else:
        scenarios = build_default_benchmark_suite()

    result = evaluate_scenarios(scenarios)
    _write_json(result, args.out_json)
    _write_markdown(result, args.out_md)
    print(json.dumps({"total_scenarios": result.total_scenarios, "out": str(args.out_json)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
