# Benchmarking and usage

This directory provides a manual benchmark workflow and a small synthetic dataset to evaluate the Decrypto assumption-driven approach against conventional signature-only scanning.

Running benchmarks locally

- Install the package in editable mode:

  python -m pip install -e .

- Run the bundled benchmark CLI using the built-in suite:

  python -m decrypto_framework.benchmark_cli --out-json artifacts/benchmarks/result.json --out-md artifacts/benchmarks/result.md

- Or run the provided suite file:

  python -m decrypto_framework.benchmark_cli --suite resources/benchmarks/default_suite.json --out-json artifacts/benchmarks/result.json --out-md artifacts/benchmarks/result.md

Running the manual GitHub Actions benchmark

- The repository includes a manual workflow (.github/workflows/benchmark.yml). Trigger it from the Actions tab to run the benchmark job.
- The workflow produces artifacts (JSON + Markdown) that you can download from the workflow run.

Safety and policy

- The benchmark suite is synthetic and does not perform network scans or contact external targets.
- CI benchmark runs are manual by design (workflow_dispatch) to avoid accidental resource usage.
