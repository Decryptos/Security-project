
## Benchmarks

A benchmark CLI is available under `decrypto_framework.benchmark_cli` that runs a small synthetic scenario suite (resources/benchmarks/default_suite.json) and exports JSON and Markdown summaries to `artifacts/benchmarks/`.

Example:

```bash
python -m decrypto_framework.benchmark_cli --suite resources/benchmarks/default_suite.json --out-json artifacts/benchmarks/result.json --out-md artifacts/benchmarks/result.md
```
