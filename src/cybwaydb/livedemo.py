"""The ONE live-model demo run (Gemini), under exclusive cost control.

Sends ONLY security configuration metadata to the model — never table
data, never passwords. Every model call is budget-charged before it
happens; the whole demo is capped by a single BudgetCeiling (default $2).
Results are scored against deterministic ground truth and written to a
run directory with the tamper-evident log + manifest, like any scan.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .agents import CheckerAgent, VERDICT_PASS
from .auditlog import AuditLog, write_manifest
from .budget import BudgetCeiling
from .providers import GeminiProvider
from .rules import run_all_rules, RULES, FAIL
from .synthdb import create_synthetic_db

CONFIG_TABLES = ("dba_users", "dba_profiles", "dba_role_privs", "dba_sys_privs",
                 "v_parameter", "dba_stmt_audit_opts", "db_metadata")


def config_snapshot(conn: sqlite3.Connection) -> str:
    """Serialize config metadata (and only config metadata) for the prompt."""
    snap = {}
    for t in CONFIG_TABLES:
        cols = [c[1] for c in conn.execute(f"PRAGMA table_info({t})")]
        snap[t] = [dict(zip(cols, row)) for row in conn.execute(f"SELECT * FROM {t}")]
    return json.dumps(snap, indent=1)


def build_prompt(conn: sqlite3.Connection) -> str:
    rule_list = "\n".join(
        f"- {f.rule_id}: {f.title}" for f in run_all_rules(create_synthetic_db()))
    return f"""You are a database security compliance auditor. Below is an Oracle-style
security configuration (synthetic test data). Evaluate it against these rules:

{rule_list}

Return ONLY a JSON array. One object per rule that FAILS, with exactly these keys:
rule_id, title, status (always "FAIL"), severity (high|medium|low),
references (array of strings), evidence (array of strings quoting the config),
remediation_sql (string; a draft for human review, never to be auto-executed).
Do not invent rules. Do not include passing rules.

CONFIGURATION:
{config_snapshot(conn)}
"""


def run_live_demo(out_dir: str | Path, budget_usd: float = 2.00, n_runs: int = 3,
                  transport=None) -> dict:
    """Run the live auditor n_runs times under one budget ceiling and
    score it against ground truth. Raises before any call if unguarded."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log = AuditLog(out_dir / "audit.log.jsonl")
    budget = BudgetCeiling(max_usd=budget_usd)
    provider = GeminiProvider(budget, opt_in=True, transport=transport)

    conn = create_synthetic_db()
    truth = {f.rule_id for f in run_all_rules(conn) if f.status == FAIL}
    checker = CheckerAgent()
    prompt = build_prompt(conn)

    tp = fp = fn = 0
    runs = []
    log.append("live_demo_started", {"model": provider.MODEL, "budget_usd": budget_usd,
                                     "n_runs": n_runs})
    for i in range(n_runs):
        raw = provider.generate(prompt)
        findings = json.loads(raw)
        adjudication = checker.adjudicate(conn, findings)
        verified = {v["finding"]["rule_id"] for v in adjudication["verdicts"]
                    if v["verdict"] == VERDICT_PASS}
        reported = {f.get("rule_id") for f in findings}
        run_tp, run_fp, run_fn = len(reported & truth), len(reported - truth), len(truth - reported)
        tp, fp, fn = tp + run_tp, fp + run_fp, fn + run_fn
        runs.append({"run": i, "tp": run_tp, "fp": run_fp, "fn": run_fn,
                     "checker_verified": len(verified),
                     "quarantined": sum(1 for v in adjudication["verdicts"]
                                        if v["verdict"] != VERDICT_PASS)})
        log.append("live_run_scored", {**runs[-1], "spent_usd": round(budget.spent_usd, 4)})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    result = {
        "provider": provider.name, "model": provider.MODEL, "n_runs": n_runs,
        "rules_total": len(RULES), "ground_truth_violations": len(truth),
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0,
        "budget_ceiling_usd": budget_usd, "spent_usd_estimate": round(budget.spent_usd, 4),
        "per_run": runs,
    }
    (out_dir / "live_benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    log.append("live_demo_completed", {k: result[k] for k in
                                       ("precision", "recall", "f1", "spent_usd_estimate")})
    write_manifest(out_dir, {"summary": result})
    return result
