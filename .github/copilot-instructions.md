Assumption-Driven Security Research Framework — Copilot Instructions

Project: Decrypto
Classification: Proprietary research methodology
Purpose: hypothesis-driven discovery, validation, risk assessment, and responsible disclosure.

Summary
- This repository implements a research-first, assumption-driven methodology: extract security assumptions, generate falsifiable hypotheses, validate experimentally in authorized environments, and correlate observations into risk assessments. Findings are leads until independently validated.

Core workflow (condensed)
1. Assumption Extraction
   - Identify explicit and implicit security assumptions in code, configs, protocols, and architecture (auth, crypto, randomness, trust boundaries, session management, caching/CORS, dependencies, isolation).
2. Hypothesis Generation
   - For each assumption, create a falsifiable hypothesis with preconditions, expected observations, test plan, and impact estimate.
3. Controlled Validation
   - Run reproducible experiments only in isolated/authorized environments. Use controls, paired observations, and replication.
4. Statistical Evaluation
   - Report confidence, effect sizes, and reproducibility. Use corrections (e.g., Holm–Bonferroni) when testing many hypotheses.
5. Vulnerability Correlation
   - Construct candidate chains across components; label theoretical vs experimentally demonstrated.
6. Risk & Reporting
   - Produce structured reports: description, violated assumption, affected component, reproduction steps, evidence/limitations, impact, remediation, and test guidance.

Design constraints
- Never perform unauthorized testing, internet-wide scans, credential harvesting, exploitation, or persistence.
- Do not transmit proprietary methodology or secrets to external services without explicit authorization.
- Do not fabricate results or statistical claims.

Three modular engines (guidance)
- Assumption Intelligence Engine: extract assumptions and generate ranked hypotheses.
- Experimental Validation Engine: run controlled tests and produce machine-readable evidence.
- Vulnerability Correlation Engine: analyze cross-component interactions and propose attack chains.

Repository integration (priority)
- Preserve modularity and provenance: separate hypothesis generation, execution, statistics, and reporting.
- Use typed Python, structured logging, JSON outputs, and unit/integration tests.
- Keep a clear opt-in boundary for any networked or history-based scans; document caching and TTL for external feeds.

First assignment for Copilot (deliverable before code changes)
1. Inspect repository and list:
   - components that already implement methodology,
   - missing scientific/validation capabilities,
   - architectural changes to improve reliability/modularity,
   - integration plan that preserves existing functionality.
2. Propose a prioritized implementation plan (files, interfaces, tests), with rationale and minimal breaking changes.
3. Provide a test matrix showing how to demonstrate improved performance vs conventional scanners.

How to use this file
- Place as .github/copilot-instructions.md to guide Copilot Chat (Agent Mode).
- Keep confidential: review Copilot privacy/data-use settings before uploading.
