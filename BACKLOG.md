# BACKLOG.md

## Done — AI layer (mock-first)

- [x] Auditor agent — done (agents.py, mock provider)
- [x] Independent checker agent — done (PASS/REVIEW/QUARANTINE, never grades own generation)
- [x] Human-in-the-loop approval gate — done (gate.py, logged, no execute path)
- [x] Budget ceiling + dry-run — done (budget.py; live provider gated on opt-in + env key)
- [x] Red-team suite — done (18 OWASP-mapped patterns, all quarantined)

## Extras

- [x] EVAL BENCHMARK — done (evalbench.py; precision 0.9987 / recall 0.8965 / F1 0.9448 @ 50 mock runs)
- [x] DRIFT DETECTION — done (drift.py + `cybwaydb drift`; regression fails CI)
- [x] INJECTION CANARY — done (all_tab_comments.EMPLOYEES_FAKE, caught by checker.scan_config)
- [x] PATCH-WATCH: Oracle public CPU calendar (Jan/Apr/Jul/Oct) — CYB-017, done
- [ ] Tagged v1.0 release

## Later / optional

- [x] POA&M-style risk acceptance in the gate — done (CA-5 structure, expiring, logged); full report generator still open
- [ ] Multi-model (Claude vs Gemini) comparison
- [ ] Model card + AI risk register
- [ ] PyPI publish (`pip install cybwaydb`) + Docker image
