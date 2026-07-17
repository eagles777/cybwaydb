# MAINTENANCE.md

How a future session (or contributor) keeps Cybwaydb healthy.

## Layout

```
src/cybwaydb/
  synthdb.py    synthetic Oracle-style catalog (SCHEMA + baseline/compliant datasets)
  rules.py      rule engine — one @rule function per check, returns Finding
  auditlog.py   hash-chained audit log + SHA-256 run manifest
  controls.py   secret-scan + policy-lint repo controls
  engine.py     scan orchestrator (rules -> findings.json + log + manifest)
  cli.py        `cybwaydb scan|verify|controls`
tests/test_core.py
```

## Dependencies

- Runtime: **stdlib only** (sqlite3, hashlib, json). Keep it that way unless there's a strong reason.
- Dev: `pytest==8.2.2` (pinned in `pyproject.toml` extras). Bump deliberately, run the full suite.

## Routine tasks

- `pytest` must pass before any merge. CI runs mock mode only — pushes never cost money.
- `cybwaydb controls` must return no hits (secret scan + policy lint). It runs in CI.
- Adding a rule: write a `@rule` function in `rules.py` with STIG/NIST citations and remediation SQL; extend both the non-compliant baseline and `compliant_rows()` in `synthdb.py` so both polarity tests stay meaningful; keep rule IDs (`CYB-0xx`) unique.
- Never commit `.env` (gitignored). API keys only in local `.env` or GitHub Actions Secrets.

## Invariants (from CLAUDE.md — do not break)

- Mock mode is the default; live LLM calls require an explicit flag plus a code-enforced budget ceiling.
- Defensive security only; synthetic data only; no copyrighted third-party benchmark content (see LEGAL.md).
- Remediation SQL is never auto-executed.
- Track progress in `PROGRESS.md`; queue work in `BACKLOG.md`.
