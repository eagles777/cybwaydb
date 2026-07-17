"""Human-in-the-loop approval gate, including POA&M-style risk acceptance.

No finding "resolves" and no remediation SQL runs without an explicit,
logged human approve/reject. There is NO execute path at all in this
codebase — dry_run() is the terminal state; it returns the SQL for a human
DBA to review and run through their own change-control process.

Risk acceptance follows the PUBLIC structure of NIST SP 800-53 rev5 CA-5
(Plan of Action and Milestones) and NIST SP 800-37 (RMF): identified
weakness, justification, compensating control, named accepter, and a
mandatory review date after which the acceptance EXPIRES and the finding
counts as open again. Generic public-domain structure only; all examples
are synthetic.
"""

from __future__ import annotations

from datetime import date

from .auditlog import AuditLog


class ApprovalRequired(RuntimeError):
    pass


class IncompleteRiskAcceptance(ValueError):
    pass


RISK_ACCEPTANCE_FIELDS = ("justification", "compensating_control", "accepted_by", "review_date")


class ApprovalGate:
    def __init__(self, log: AuditLog):
        self.log = log
        self._decisions: dict[str, dict] = {}

    def submit(self, finding: dict, checker_verdict: str) -> None:
        rid = finding["rule_id"]
        self._decisions[rid] = {"status": "pending", "checker_verdict": checker_verdict}
        self.log.append("finding_submitted", {"rule_id": rid, "checker_verdict": checker_verdict})

    def approve(self, rule_id: str, approver: str, reason: str) -> None:
        self._decide(rule_id, "approved", approver, reason)

    def reject(self, rule_id: str, approver: str, reason: str) -> None:
        self._decide(rule_id, "rejected", approver, reason)

    def _decide(self, rule_id: str, decision: str, approver: str, reason: str) -> None:
        if rule_id not in self._decisions:
            raise KeyError(f"finding {rule_id} was never submitted to the gate")
        if not approver or not reason:
            raise ValueError("approver and reason are mandatory (logged)")
        self._decisions[rule_id].update(status=decision, approver=approver, reason=reason)
        self.log.append(f"finding_{decision}", {"rule_id": rule_id, "approver": approver, "reason": reason})

    def accept_risk(self, rule_id: str, *, justification: str, compensating_control: str,
                    accepted_by: str, review_date: str) -> dict:
        """Third decision path (NIST CA-5 style): a HUMAN accepts the risk.
        Every field is mandatory; the acceptance expires at review_date."""
        if rule_id not in self._decisions:
            raise KeyError(f"finding {rule_id} was never submitted to the gate")
        record = {
            "justification": justification,
            "compensating_control": compensating_control,
            "accepted_by": accepted_by,
            "review_date": review_date,
        }
        blank = [k for k in RISK_ACCEPTANCE_FIELDS if not str(record[k]).strip()]
        if blank:
            raise IncompleteRiskAcceptance(f"risk acceptance rejected — blank fields: {blank}")
        date.fromisoformat(review_date)  # must be a valid ISO date
        self._decisions[rule_id].update(status="risk_accepted", **record)
        self.log.append("finding_risk_accepted", {"rule_id": rule_id, **record})
        return dict(self._decisions[rule_id])

    def status(self, rule_id: str, as_of: date | None = None) -> str:
        """Current state. A risk acceptance whose review_date has passed
        reverts to 'expired' — the finding counts as open again."""
        d = self._decisions.get(rule_id)
        if d is None:
            return "unsubmitted"
        if d["status"] == "risk_accepted" and as_of is not None:
            if as_of > date.fromisoformat(d["review_date"]):
                return "expired"
        return d["status"]

    def open_findings(self, as_of: date) -> list[str]:
        """Rule IDs still requiring attention: pending, rejected, or expired."""
        return [rid for rid in self._decisions
                if self.status(rid, as_of=as_of) in ("pending", "rejected", "expired")]

    def dry_run_remediation(self, finding: dict) -> dict:
        """Return the remediation SQL as a dry-run plan. Never executes.
        Requires prior explicit human approval."""
        rid = finding["rule_id"]
        if self.status(rid) != "approved":
            raise ApprovalRequired(
                f"finding {rid} is '{self.status(rid)}' — remediation requires explicit human approval")
        plan = {"rule_id": rid, "sql": finding.get("remediation_sql", ""), "executed": False,
                "note": "dry run only; execution is out of scope by design"}
        self.log.append("remediation_dry_run", plan)
        return plan
