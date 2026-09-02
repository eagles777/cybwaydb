# NIST AI RMF 1.0 — Control Mapping for Cybwaydb

This document maps Cybwaydb's implemented controls to the four core functions of the
**NIST AI Risk Management Framework (AI RMF 1.0)** — GOVERN, MAP, MEASURE, MANAGE.
The AI RMF is a US Government work (public domain); function and category names are
referenced by identifier. Each row cites the code or artifact in this repository that
implements the control, so every claim here is verifiable by reading the source.

Scope note: Cybwaydb is a single-developer portfolio project. This mapping documents how
its design applies AI RMF principles; it is not a claim of organizational AI RMF
conformance, third-party assessment, or certification.

---

## GOVERN — policies, accountability, and human oversight

| AI RMF category | How Cybwaydb implements it | Evidence in repo |
|---|---|---|
| GOVERN 1 — Policies and procedures for AI risk are in place and transparent | Hard rules are written down and enforced in code: defensive-only scope, synthetic-data-only, mock-by-default, zero-spend cost policy, privacy constraints. Automated policy-lint fails the build on violations. | `CLAUDE.md`, `LEGAL.md`, `src/cybwaydb/controls.py` (`policy_lint`, `secret_scan`), `cybwaydb controls` |
| GOVERN 2 — Accountability structures; roles and responsibilities | A named human approver is required on every decision. Approve/reject/risk-accept all record `approver`/`accepted_by`, and blank names are rejected. | `src/cybwaydb/gate.py` (`approve`, `reject`, `accept_risk`, `IncompleteRiskAcceptance`) |
| GOVERN 3 — Human oversight; humans remain in the loop for consequential decisions | No AI output takes effect without a logged human decision. There is **no execute path** in the codebase; remediation is dry-run only. AI may *draft* risk-acceptance paperwork but the draft is unsigned by construction and cannot be accepted as-is. | `src/cybwaydb/gate.py` (`dry_run_remediation`, `ApprovalRequired`), `src/cybwaydb/agents.py` (`draft_risk_acceptance`), `tests/test_risk_acceptance.py::test_ai_draft_can_never_be_accepted_as_is` |
| GOVERN 4 — Organizational practices for transparency and documentation | Architecture, benchmarks, limitations, and provenance are published in the repo rather than hidden. | `README.md`, `BENCHMARKS.md`, `LEGAL.md`, `docs/evidence/` |
| GOVERN 6 — Third-party / supply-chain risk | Runtime is stdlib-only by design (no third-party runtime dependencies); dev dependencies are pinned. LLM providers are pluggable and gated. | `pyproject.toml`, `MAINTENANCE.md`, `src/cybwaydb/providers.py` |

## MAP — context, intended use, and risk identification

| AI RMF category | How Cybwaydb implements it | Evidence in repo |
|---|---|---|
| MAP 1 — Context and intended purpose are established | Purpose is narrowly defined: audit database *security configuration* against public DISA STIG / NIST SP 800-53 rules. Out-of-scope uses (offensive tooling, real data, autonomous remediation) are explicitly prohibited. | `README.md` ("Safety & scope"), `CLAUDE.md` |
| MAP 2 — AI system categorization; what the model does and does not do | The LLM's role is bounded: it drafts findings and remediation SQL as strict JSON. It does not decide, execute, or self-verify. Ground truth is a deterministic rule engine, not the model. | `src/cybwaydb/agents.py` (`AuditorAgent`), `src/cybwaydb/rules.py` |
| MAP 3 — Benefits and costs; resource constraints | Cost is a mapped risk: a code-enforced budget ceiling is charged *before* every network call and refuses calls that would exceed it. Default operation is $0 mock mode. | `src/cybwaydb/budget.py` (`BudgetCeiling`, `BudgetExceeded`), `src/cybwaydb/livedemo.py` |
| MAP 4 — Risks and impacts to individuals and data | Only configuration *metadata* is ever sent to a model — never table contents, never credentials. The synthetic catalog includes a planted injection canary so data-borne attacks on the model are exercised, not assumed. | `src/cybwaydb/livedemo.py` (prompt construction), `src/cybwaydb/synthdb.py`, `src/cybwaydb/redteam.py` (`CANARY_COMMENT`) |
| MAP 5 — Likelihood and magnitude of impact | Findings carry severity (high/medium/low) and cited references, so impact is explicit per finding rather than implied. | `src/cybwaydb/rules.py` |

## MEASURE — evaluation, testing, and monitoring

| AI RMF category | How Cybwaydb implements it | Evidence in repo |
|---|---|---|
| MEASURE 1 — Appropriate methods and metrics are identified and applied | Model output is scored against deterministic ground truth using precision, recall, and F1 over N seeded runs. | `src/cybwaydb/evalbench.py`, `cybwaydb benchmark`, `BENCHMARKS.md` |
| MEASURE 2 — AI systems are evaluated for trustworthy characteristics (validity, reliability, security, resilience) | **Validity/reliability:** live-model precision 1.00 / recall 0.94 / F1 0.97 (3 runs); mock harness 50 runs. **Security/resilience:** red-team suite of 18 OWASP LLM Top 10-mapped injection, jailbreak, and exfiltration patterns — all quarantined. **Independence:** a separate checker re-derives truth from raw config and never grades its own generation. | `docs/evidence/live-run/live_benchmark.json`, `src/cybwaydb/redteam.py`, `tests/test_ai_layer.py::test_redteam_pipeline_quarantines_each_pattern`, `src/cybwaydb/agents.py` (`CheckerAgent`) |
| MEASURE 2.7 — Security and resilience are evaluated | Prompt-injection detection runs on both AI output (findings) and raw input data (`scan_config`). Tainted findings are quarantined, not merely flagged. | `src/cybwaydb/agents.py` (`CheckerAgent.adjudicate`, `scan_config`), `cybwaydb redteam` |
| MEASURE 3 — Mechanisms for tracking identified risks over time | Drift detection diffs posture between scans (regressed / fixed / evidence-changed); a regression fails the pipeline. | `src/cybwaydb/drift.py`, `cybwaydb drift`, `tests/test_drift.py` |
| MEASURE 4 — Measurement results are documented and shared | Benchmark results and the raw evidence of the live run are committed, including a hash-chained log whose integrity can be re-verified by anyone. | `BENCHMARKS.md`, `docs/evidence/README.md`, `cybwaydb verify` |

## MANAGE — responding to and managing risks

| AI RMF category | How Cybwaydb implements it | Evidence in repo |
|---|---|---|
| MANAGE 1 — Risks are prioritized and responded to | Every finding is adjudicated PASS / REVIEW / QUARANTINE by the independent checker before a human sees it; severity ordering drives the report. | `src/cybwaydb/agents.py`, `src/cybwaydb/report.py` |
| MANAGE 2 — Strategies to maximize benefits and minimize negative impacts; residual-risk documentation | A formal risk-acceptance path exists, structured per NIST SP 800-53 CA-5 (POA&M-style): mandatory justification, compensating control, named accepter, and an **expiring** review date after which the finding reopens. Risk-accepted findings still cannot run remediation. | `src/cybwaydb/gate.py` (`accept_risk`, `open_findings`), `tests/test_risk_acceptance.py` |
| MANAGE 3 — Third-party risks are managed | Live providers require explicit opt-in **and** an environment key **and** a budget; absent any one, the provider refuses to construct. CI never has a key. | `src/cybwaydb/providers.py` (`LiveProvider`, `GeminiProvider`), `tests/test_ai_layer.py::test_live_provider_refuses_without_opt_in_and_key` |
| MANAGE 4 — Incident response, recovery, and post-deployment monitoring | Tamper-evident hash-chained audit log detects any edit, deletion, or reordering of the record; SHA-256 manifest detects post-run tampering of outputs. Both are verified by `cybwaydb verify` and covered by tamper tests. | `src/cybwaydb/auditlog.py` (`AuditLog.verify_chain`, `verify_manifest`), `tests/test_core.py` |

---

## Known gaps (honest limitations)

- No formal bias/fairness evaluation (MEASURE 2.11) — not applicable to configuration auditing, but not evaluated either.
- Single-model live evaluation (Google Gemini); multi-model comparison is on the backlog.
- No production deployment, so post-deployment monitoring (MANAGE 4) is demonstrated via drift detection between scans rather than live telemetry.
- This mapping is self-assessed by the author, not independently audited.

*Reference: NIST AI 100-1, Artificial Intelligence Risk Management Framework (AI RMF 1.0), January 2023. Public domain (US Government work).*
