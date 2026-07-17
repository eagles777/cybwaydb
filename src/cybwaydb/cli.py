"""Command-line interface for Cybwaydb (core, mock mode only)."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .auditlog import AuditLog, verify_manifest
from .controls import policy_lint, secret_scan
from .engine import run_scan
from .synthdb import create_synthetic_db


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cybwaydb",
        description="Governed-AI database compliance auditor (mock mode, $0, defensive only)",
    )
    parser.add_argument("--version", action="version", version=f"cybwaydb {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run all STIG/NIST rules against a database")
    p_scan.add_argument("--out", default="runs/latest", help="Run output directory")
    p_scan.add_argument("--db", default=None,
                        help="Path to a SQLite catalog file to scan. Omit to use the built-in synthetic DB.")

    p_init = sub.add_parser("init-db", help="Write a synthetic catalog to a SQLite file you can edit and re-scan")
    p_init.add_argument("--out", default="cybwaydb_sample.sqlite")

    p_verify = sub.add_parser("verify", help="Verify audit-log chain and run manifest")
    p_verify.add_argument("--run-dir", default="runs/latest")

    p_ctl = sub.add_parser("controls", help="Run policy-lint and secret-scan over the repo")
    p_ctl.add_argument("--root", default=".")

    p_bench = sub.add_parser("benchmark", help="Measure auditor precision/recall vs ground truth (mock, $0)")
    p_bench.add_argument("--runs", type=int, default=50)
    p_bench.add_argument("--seed", type=int, default=42)

    sub.add_parser("redteam", help="Scan raw config for published OWASP-LLM injection patterns (incl. canary)")

    p_live = sub.add_parser("live-demo", help="ONE budget-capped live Gemini run (requires GOOGLE_API_KEY)")
    p_live.add_argument("--budget", type=float, default=2.00, help="Hard cost ceiling in USD (default 2.00)")
    p_live.add_argument("--runs", type=int, default=3)
    p_live.add_argument("--out", default="runs/live-demo")
    p_live.add_argument("--i-understand-costs", action="store_true",
                        help="Required. Confirms you know this makes real API calls.")

    p_drift = sub.add_parser("drift", help="Diff security posture between two scans")
    p_drift.add_argument("--old", required=True, help="Previous run's findings.json")
    p_drift.add_argument("--new", required=True, help="Latest run's findings.json")

    p_report = sub.add_parser("report", help="Generate a standalone HTML compliance report from a run")
    p_report.add_argument("--run-dir", default="runs/latest")
    p_report.add_argument("--out", default="report.html")
    p_report.add_argument("--live-benchmark", default=None,
                          help="Optional path to live_benchmark.json to include real-model numbers")

    args = parser.parse_args(argv)

    if args.command == "scan":
        if args.db:
            import sqlite3
            conn = sqlite3.connect(args.db)
        else:
            conn = create_synthetic_db()
        summary = run_scan(conn, args.out)
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "init-db":
        create_synthetic_db(args.out).close()
        print(f"Synthetic catalog written to {args.out}. "
              f"Open it in any SQLite browser, edit the rows, then: cybwaydb scan --db {args.out}")
        return 0

    if args.command == "verify":
        log_ok, msg = AuditLog(f"{args.run_dir}/audit.log.jsonl").verify_chain()
        man_ok, problems = verify_manifest(args.run_dir)
        print(f"audit log: {msg}")
        print(f"manifest: {'ok' if man_ok else problems}")
        return 0 if (log_ok and man_ok) else 1

    if args.command == "controls":
        secrets = secret_scan(args.root)
        policy = policy_lint(args.root)
        print(json.dumps({"secret_scan_hits": secrets, "policy_violations": policy}, indent=2))
        return 0 if not (secrets or policy) else 1

    if args.command == "benchmark":
        from .evalbench import run_benchmark
        result = run_benchmark(n_runs=args.runs, base_seed=args.seed)
        result.pop("per_run")
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "live-demo":
        if not args.i_understand_costs:
            print("Refusing: pass --i-understand-costs to confirm real API calls. "
                  "Everything else in this tool is free; only this command can cost money.")
            return 1
        if args.budget > 2.00:
            print(f"Refusing: budget ${args.budget:.2f} exceeds the project's $2.00 demo policy.")
            return 1
        from .livedemo import run_live_demo
        result = run_live_demo(args.out, budget_usd=args.budget, n_runs=args.runs)
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "report":
        from .report import write_report
        out = write_report(args.run_dir, args.out, live_benchmark_path=args.live_benchmark)
        print(f"Report written to {out} — open it in any browser.")
        return 0

    if args.command == "drift":
        from .drift import diff_postures, load_findings
        d = diff_postures(load_findings(args.old), load_findings(args.new))
        print(json.dumps(d, indent=2))
        return 0 if d["verdict"] != "REGRESSED" else 1  # CI-friendly: regression fails the pipeline

    if args.command == "redteam":
        from .agents import CheckerAgent
        hits = CheckerAgent().scan_config(create_synthetic_db())
        print(json.dumps({"injection_hits": hits}, indent=2))
        return 0 if hits else 1  # the canary MUST be caught

    return 2


if __name__ == "__main__":
    sys.exit(main())
