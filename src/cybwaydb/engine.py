"""Scan orchestrator: run all rules against a catalog DB, write findings,
hash-chained audit log, and SHA-256 manifest into a run directory.

Mock mode only in the core — no network, no API key, $0.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .auditlog import AuditLog, write_manifest
from .rules import run_all_rules, FAIL


def run_scan(conn: sqlite3.Connection, out_dir: str | Path) -> dict:
    """Run every rule, persist findings.json + audit log + manifest.
    Returns a summary dict."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log = AuditLog(out_dir / "audit.log.jsonl")

    log.append("scan_started", {"mode": "mock", "cost_usd": 0})
    findings = run_all_rules(conn)
    for f in findings:
        log.append("rule_evaluated", {"rule_id": f.rule_id, "status": f.status})

    findings_dicts = [f.to_dict() for f in findings]
    (out_dir / "findings.json").write_text(
        json.dumps(findings_dicts, indent=2), encoding="utf-8"
    )

    summary = {
        "total": len(findings),
        "passed": sum(1 for f in findings if f.status != FAIL),
        "failed": sum(1 for f in findings if f.status == FAIL),
        "mode": "mock",
        "cost_usd": 0,
    }
    log.append("scan_completed", summary)
    write_manifest(out_dir, {"summary": summary})
    return summary
