# Decrypto Security Research Framework

This repository now follows an assumption-driven security research architecture rather than a single-purpose scanner. The project is organized around three research engines and a thin compatibility layer that preserves the current repository tools.

## Architecture

- Assumption Intelligence Engine
  - identifies assumptions related to auth, trust boundaries, cryptography, caching, CORS, session state, and dependency exposure
  - converts assumptions into testable hypotheses
- Experimental Validation Engine
  - executes reproducible experiments in isolated or authorized environments
  - tracks observations, controls, and evidence provenance
- Vulnerability Correlation Engine
  - correlates independent observations across components and trust boundaries
  - distinguishes correlated concerns from confirmed exploit chains

## Current project components

- `decrypto_assumption_scan.py` - live HTTP/OpenAPI auditor that records unconfirmed leads only
- `decrypto_crypto_checks.py` - static crypto anti-pattern scanner
- `secure_crypto_examples.py` - safe Python cryptography examples
- `src/decrypto_framework/` - modular framework scaffold for assumption extraction, validation, and correlation
- `tests/` - regression and framework validation tests

## Scientific and design goals

- preserve legacy functionality while separating modeling, experiments, and correlation
- prefer evidence-based, reproducible, stateless validation over speculative findings
- keep all proprietary, sensitive, or experimental methodology local and explicitly authorized
- avoid fabricating vulnerabilities or claiming exploitability without owner validation

## Quick start

Install the project in editable mode and run the framework CLI:

```bash
python -m pip install -e .
python -m decrypto_framework.cli --repo-root .
```

Run tests:

```bash
pytest -q
```

## Compatibility

The original repository scripts remain intact and should continue to work. The new framework module sits alongside them and provides a cleaner separation of concerns, making it easier to extend the methodology without disrupting the current audit flow.
