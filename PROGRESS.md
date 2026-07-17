# PROGRESS.md

## Session 1 — 2026-07-17 — CORE built (mock mode, $0)

Done:
- CLAUDE.md project rules established
- Package scaffold: `pyproject.toml` (Apache-2.0, stdlib runtime, pytest==8.2.2 dev pin), src layout, `cybwaydb` CLI
- `synthdb.py`: synthetic SQLite catalog mimicking Oracle views (dba_users, dba_profiles, dba_role_privs, dba_sys_privs, v$parameter, dba_stmt_audit_opts) — deliberately non-compliant baseline + hardened `compliant_rows()` variant, all fake data
- `rules.py`: 16 rules CYB-001..CYB-016 (password policy, default accounts, expired accounts, DBA/PUBLIC/ANY/ADMIN OPTION privileges, audit_trail, logon auditing, secure init params), each with DISA STIG + NIST 800-53r5 citations and remediation SQL (never auto-executed)
- `auditlog.py`: hash-chained JSONL audit log (verify_chain detects edit/delete/reorder) + SHA-256 run manifest
- `controls.py`: secret-scan (6 credential patterns) + policy-lint (CIS-content ban, unignored-.env check)
- `engine.py` + `cli.py`: scan / verify / controls commands
- Tests: 17 passing (both rule polarities, tamper detection x3, manifest tamper, e2e scan, controls)
- Docs: README, LEGAL.md, NOTICE, MAINTENANCE.md, BACKLOG.md; CI workflow (mock mode)

Verified: `pytest` -> 17 passed; `cybwaydb scan` -> 16/16 findings on baseline; `cybwaydb verify` -> chain intact, manifest ok; `cybwaydb controls` -> clean.

Next: STOPPED for user approval before the AI layer (see BACKLOG.md).

## Session 2 — 2026-07-17 — PATCH-WATCH added

- `patchwatch.py`: quarterly CPU cycle math (Tuesday-closest-to-17th heuristic + published-date overrides, e.g. Oct 2025 = Oct 21), CURRENT/BEHIND/UNKNOWN classification with cycles-behind count
- Rule CYB-017 (high, NIST SI-2): fails baseline (3 cycles behind), passes compliant DB; deterministic via frozen scan_date in db_metadata
- 22 tests passing; controls clean
- Next: still awaiting approval for AI layer

## Session 2 (cont.) — 2026-07-17 — AI GOVERNANCE LAYER built (mock, $0)

- providers.py: MockProvider (seeded, deliberately imperfect: 10% miss / 5% fabricate) + guarded LiveProvider stub (opt-in + env key + budget required)
- budget.py: BudgetCeiling with dry_run before charge; BudgetExceeded blocks the call
- agents.py: AuditorAgent (strict-JSON findings) + CheckerAgent (independent, re-derives ground truth from raw config; PASS/REVIEW/QUARANTINE; scan_config catches raw-config injections)
- gate.py: ApprovalGate — submit/approve/reject logged to hash chain; dry-run only, NO execute path
- redteam.py: 18 OWASP LLM Top 10-mapped patterns + injection canary seeded in all_tab_comments
- evalbench.py: precision/recall benchmark — 50 runs: precision 0.9987, recall 0.8965, F1 0.9448
- CLI: added `cybwaydb benchmark` and `cybwaydb redteam`
- 57 tests passing (was 22); controls clean

## Session 2 (cont.) — 2026-07-17 — RISK ACCEPTANCE (POA&M-style) built

- gate.py: third decision path accept_risk() per public NIST CA-5 structure — justification, compensating control, named accepter, mandatory ISO review_date; blank fields rejected (IncompleteRiskAcceptance); acceptance expires after review_date and the finding reopens (open_findings); risk-accepted still cannot dry-run remediation
- agents.py: draft_risk_acceptance() — AI drafts paperwork with accepted_by/review_date intentionally blank so a draft can never be accepted as-is; human must complete and sign
- All decisions logged to the hash chain
- 67 tests passing (was 57); controls clean

## Session 2 (cont.) — 2026-07-17 — DRIFT DETECTION built

- drift.py: diff two scans -> regressed / fixed / still_failing / evidence_changed / rules added-removed; verdict REGRESSED|IMPROVED|UNCHANGED
- CLI `cybwaydb drift --old --new` (exit 1 on regression, CI-friendly)
- 72 tests passing; ALL plan features now built except: merge/tag v1.0 (needs user), one live demo run (needs API key + user go)

## Session 2 (cont.) — 2026-07-17 — LIVE DEMO harness (Gemini) built, NOT yet run

- providers.py: GeminiProvider — requires opt_in + GOOGLE_API_KEY env; budget charged BEFORE every network call; injectable transport so tests stay offline
- livedemo.py: one budget-capped demo — config metadata only in prompt (canary/app tables excluded), checker adjudicates every finding, precision/recall scored vs ground truth, results + hash-chained log + manifest written to run dir
- CLI `cybwaydb live-demo`: refuses without --i-understand-costs; refuses budget > \$2.00 (project policy)
- 79 tests passing, all offline (fake transport); CI still \$0
- Repo visibility: PRIVATE (verified via GitHub API this session)
- NEXT: user creates free-tier Google AI Studio key (NO billing enabled), puts it in gitignored .env, then we run the one live demo

## Session 2 (cont.) — 2026-07-17 — LIVE DEMO RUN COMPLETED (Google Gemini)

- Key loaded via env; gemini-2.0-flash returned 429 (free_tier limit 0 for that model)
- Probed models -> gemini-flash-lite-latest has free quota; set as default (env-overridable GEMINI_MODEL)
- LIVE RESULT (3 runs): precision 1.000, recall 0.9412, F1 0.9697; 16/17 TP per run, 0 FP; checker verified 16/16 each run
- Cost: ~$0.03 estimated ceiling charge; $0.00 actual on free tier; $2 hard cap enforced
- Live run written with intact hash-chain + manifest; BENCHMARKS.md records mock + live numbers
- 79 tests still passing
- ACTION FOR OWNER: regenerate/delete the Google API key (it was placed in the plaintext env-vars box)

## Session 2 (cont.) — 2026-07-17 — HTML REPORT dashboard built

- report.py: build_report_data + render_report_html (standalone + embed); self-contained, theme-aware, no external assets, no JS
- CLI `cybwaydb report --run-dir --out [--live-benchmark]`
- Renders verdict, KPIs, 3-stage governance pipeline, live+mock benchmark meters, integrity status, all findings with severity stripes/evidence/SQL/citations
- report.html is generated output (gitignored)
- 84 tests passing

## Session 2 (cont.) — 2026-07-17 — FEED-YOUR-OWN-DATA + report committed

- CLI: `cybwaydb init-db --out FILE` writes the synthetic catalog to a real SQLite file; `cybwaydb scan --db FILE` scans any SQLite catalog the user provides (edit rows -> re-scan -> see changed findings). Verified: locking SCOTT drops it from CYB-006 evidence.
- HTML report feature (report.py + CLI) committed
- 86 tests passing
- Published a private Artifact snapshot of the report for the owner to view on screen

## Session 2 (cont.) — 2026-07-17 — INTERACTIVE PUBLIC DEMO + name kept as V. Vikram

- docs/demo.html: fully client-side interactive demo — visitor edits synthetic Oracle security settings, all 17 rules re-run live in-browser (JS mirrors rules.py incl. CPU cycle math, verified vs Python in Node). No API key, no network, no cost — safe for public hosting (GitHub Pages).
- Name: user briefly considered "V. Vikram" then chose to KEEP full name "V. Vikram" — reverted everywhere.
- Published private Artifact previews: report + interactive demo.
- 86 tests passing; controls clean.
- REPO STILL PRIVATE — awaiting explicit final confirmation before going public.

## Session 2 (cont.) — 2026-07-17 — README redesigned for public presentation
- Attractive README: centered hero, badges, embedded screenshots (demo + report, captured via headless Chromium), Mermaid governance diagram (renders natively on GitHub), benchmark table, quick start
- docs/screenshot-demo-dark.png + docs/screenshot-report-dark.png committed
- 86 tests passing; controls clean; repo STILL PRIVATE pending final go
