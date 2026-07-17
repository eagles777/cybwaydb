"""AI layer: auditor agent + independent checker agent.

Governance invariants:
- The checker NEVER grades its own generation: it re-derives ground truth
  from the raw configuration with the deterministic rule engine and checks
  the auditor's output against it.
- Every finding is adjudicated PASS / REVIEW / QUARANTINE.
- Nothing here executes SQL, resolves a finding, or spends money.
"""

from __future__ import annotations

import json
import sqlite3

from .redteam import scan_text_for_injection
from .rules import run_all_rules, FAIL

VERDICT_PASS = "PASS"            # verified against raw config
VERDICT_REVIEW = "REVIEW"        # malformed / incomplete -> human must look
VERDICT_QUARANTINE = "QUARANTINE"  # fabricated or injection-tainted

REQUIRED_FIELDS = {"rule_id", "title", "status", "severity", "references", "evidence", "remediation_sql"}


class AuditorAgent:
    """Reads config, asks the provider for strict-JSON findings."""

    def __init__(self, provider):
        self.provider = provider

    def audit(self, conn: sqlite3.Connection) -> list[dict]:
        ground_truth = [f.to_dict() for f in run_all_rules(conn) if f.status == FAIL]
        raw = self.provider.complete(
            prompt="Audit this database security configuration; respond with strict JSON findings.",
            ground_truth_findings=ground_truth,
        )
        findings = json.loads(raw)  # strict JSON or it raises
        if not isinstance(findings, list):
            raise ValueError("auditor output must be a JSON list of findings")
        return findings


def draft_risk_acceptance(finding: dict) -> dict:
    """AI-drafted POA&M-style exception paperwork (mock, $0).

    Deliberately leaves accepted_by BLANK: the gate refuses blank fields,
    so an AI draft can never be accepted as-is — a human must complete
    and sign it. That is the governance invariant, encoded.
    """
    return {
        "rule_id": finding["rule_id"],
        "justification": (f"[DRAFT — human must review] Remediation for '{finding['title']}' "
                          "is operationally constrained; see evidence: "
                          + "; ".join(finding.get("evidence", []))),
        "compensating_control": "[DRAFT — human must specify the compensating control]",
        "accepted_by": "",   # intentionally blank: only a human may sign
        "review_date": "",   # intentionally blank: human sets the expiry
        "draft": True,
    }


class CheckerAgent:
    """Independent verifier. Deterministic; re-reads the RAW config itself."""

    TEXT_CONFIG_SOURCES = (
        ("all_tab_comments", "table_name", "comments"),
        ("db_metadata", "key", "value"),
    )

    def scan_config(self, conn: sqlite3.Connection) -> list[dict]:
        """Scan raw text config fields (table comments, metadata) for
        published injection patterns BEFORE they reach any LLM prompt.
        This is what catches the injection canary."""
        hits = []
        for table, key_col, text_col in self.TEXT_CONFIG_SOURCES:
            for key, text in conn.execute(f"SELECT {key_col}, {text_col} FROM {table}"):
                for hit in scan_text_for_injection(text):
                    hits.append({**hit, "source": f"{table}.{key}"})
        return hits

    def adjudicate(self, conn: sqlite3.Connection, auditor_findings: list[dict]) -> dict:
        truth = {f.rule_id: f.to_dict() for f in run_all_rules(conn) if f.status == FAIL}
        verdicts = []
        for f in auditor_findings:
            missing = REQUIRED_FIELDS - set(f)
            tainted = [hit for field in ("title", "evidence", "remediation_sql")
                       for hit in scan_text_for_injection(json.dumps(f.get(field, "")))]
            if tainted:
                verdict, reason = VERDICT_QUARANTINE, f"injection patterns detected: {sorted({t['owasp'] for t in tainted})}"
            elif f.get("rule_id") not in truth:
                verdict, reason = VERDICT_QUARANTINE, "not verifiable against raw configuration (possible fabrication)"
            elif missing:
                verdict, reason = VERDICT_REVIEW, f"missing required fields: {sorted(missing)}"
            elif f.get("status") != truth[f["rule_id"]]["status"]:
                verdict, reason = VERDICT_REVIEW, "status disagrees with raw configuration"
            else:
                verdict, reason = VERDICT_PASS, "verified against raw configuration"
            verdicts.append({"finding": f, "verdict": verdict, "reason": reason})

        reported_ids = {f.get("rule_id") for f in auditor_findings}
        missed = [truth[rid] for rid in truth if rid not in reported_ids]
        return {"verdicts": verdicts, "missed_violations": missed}
