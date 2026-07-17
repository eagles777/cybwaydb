"""Risk acceptance (POA&M-style, NIST CA-5 public structure) tests.

Covers every promise made in the feature spec:
- third decision path with mandatory paperwork
- blank fields rejected
- everything logged to the tamper-evident chain
- acceptance expires at review_date -> finding is open again
- AI can only DRAFT the paperwork; a draft can never be accepted as-is
"""

from datetime import date

import pytest

from cybwaydb.agents import draft_risk_acceptance, VERDICT_PASS
from cybwaydb.auditlog import AuditLog
from cybwaydb.gate import ApprovalGate, ApprovalRequired, IncompleteRiskAcceptance
from cybwaydb.rules import run_all_rules
from cybwaydb.synthdb import create_synthetic_db

PAPERWORK = dict(
    justification="Legacy synthetic app FAKEAPP requires this account until decommission.",
    compensating_control="Account restricted to one host; activity audited BY ACCESS.",
    accepted_by="reviewer",
    review_date="2026-10-01",
)


@pytest.fixture
def gate_and_finding(tmp_path):
    gate = ApprovalGate(AuditLog(tmp_path / "a.jsonl"))
    finding = run_all_rules(create_synthetic_db())[0].to_dict()
    gate.submit(finding, VERDICT_PASS)
    return gate, finding


def test_risk_acceptance_happy_path_is_logged(gate_and_finding):
    gate, f = gate_and_finding
    gate.accept_risk(f["rule_id"], **PAPERWORK)
    assert gate.status(f["rule_id"], as_of=date(2026, 7, 17)) == "risk_accepted"
    events = [e["event"] for e in gate.log.entries()]
    assert events[-1] == "finding_risk_accepted"
    logged = gate.log.entries()[-1]["detail"]
    assert logged["accepted_by"] == "reviewer" and logged["review_date"] == "2026-10-01"
    ok, msg = gate.log.verify_chain()
    assert ok, msg


@pytest.mark.parametrize("blank_field", ["justification", "compensating_control", "accepted_by", "review_date"])
def test_blank_paperwork_field_is_rejected(gate_and_finding, blank_field):
    gate, f = gate_and_finding
    incomplete = {**PAPERWORK, blank_field: "   "}
    with pytest.raises(IncompleteRiskAcceptance, match=blank_field):
        gate.accept_risk(f["rule_id"], **incomplete)
    assert gate.status(f["rule_id"]) == "pending"  # nothing changed


def test_invalid_review_date_is_rejected(gate_and_finding):
    gate, f = gate_and_finding
    with pytest.raises(ValueError):
        gate.accept_risk(f["rule_id"], **{**PAPERWORK, "review_date": "next quarter"})


def test_acceptance_expires_and_finding_reopens(gate_and_finding):
    gate, f = gate_and_finding
    gate.accept_risk(f["rule_id"], **PAPERWORK)
    rid = f["rule_id"]
    assert gate.status(rid, as_of=date(2026, 10, 1)) == "risk_accepted"   # on the review date
    assert gate.status(rid, as_of=date(2026, 10, 2)) == "expired"         # day after
    assert rid in gate.open_findings(as_of=date(2026, 10, 2))
    assert rid not in gate.open_findings(as_of=date(2026, 9, 1))


def test_risk_accepted_finding_still_cannot_run_remediation(gate_and_finding):
    gate, f = gate_and_finding
    gate.accept_risk(f["rule_id"], **PAPERWORK)
    with pytest.raises(ApprovalRequired):
        gate.dry_run_remediation(f)  # accepted-risk != approved-to-remediate


def test_unsubmitted_finding_cannot_be_risk_accepted(tmp_path):
    gate = ApprovalGate(AuditLog(tmp_path / "a.jsonl"))
    with pytest.raises(KeyError):
        gate.accept_risk("CYB-001", **PAPERWORK)


def test_ai_draft_can_never_be_accepted_as_is(gate_and_finding):
    gate, f = gate_and_finding
    draft = draft_risk_acceptance(f)
    assert draft["draft"] is True and draft["accepted_by"] == ""
    with pytest.raises(IncompleteRiskAcceptance):
        gate.accept_risk(f["rule_id"], justification=draft["justification"],
                         compensating_control=draft["compensating_control"],
                         accepted_by=draft["accepted_by"], review_date=draft["review_date"])
    # human completes and signs the draft -> now it is acceptable
    gate.accept_risk(f["rule_id"], justification=draft["justification"],
                     compensating_control="Synthetic host restriction + BY ACCESS auditing.",
                     accepted_by="reviewer", review_date="2026-10-01")
    assert gate.status(f["rule_id"], as_of=date(2026, 7, 17)) == "risk_accepted"
