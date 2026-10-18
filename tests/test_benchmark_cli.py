from __future__ import annotations

import json
from pathlib import Path

from decrypto_framework.benchmark_cli import _write_json, _write_markdown
from decrypto_framework.benchmark import build_default_benchmark_suite, evaluate_scenarios


def test_cli_writes_outputs(tmp_path: Path):
    suite = build_default_benchmark_suite()
    result = evaluate_scenarios(suite)
    out_json = tmp_path / "result.json"
    out_md = tmp_path / "result.md"
    _write_json(result, out_json)
    _write_markdown(result, out_md)

    assert out_json.exists()
    assert out_md.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["total_scenarios"] == result.total_scenarios
