"""Drift detection tests: regressions, fixes, evidence-level changes."""

import copy

from cybwaydb.drift import diff_postures
from cybwaydb.rules import run_all_rules
from cybwaydb.synthdb import create_synthetic_db, compliant_rows


def _findings(rows=None):
    return [f.to_dict() for f in run_all_rules(create_synthetic_db(rows=rows))]


def test_identical_scans_show_no_drift():
    a = _findings()
    d = diff_postures(a, a)
    assert d["verdict"] == "UNCHANGED"
    assert d["regressed"] == d["fixed"] == d["evidence_changed"] == []
    assert len(d["still_failing"]) == len(a)


def test_hardening_shows_as_fixed():
    d = diff_postures(_findings(), _findings(rows=compliant_rows()))
    assert d["verdict"] == "IMPROVED"
    assert d["regressed"] == []
    assert len(d["fixed"]) == len(_findings())


def test_regression_is_detected():
    d = diff_postures(_findings(rows=compliant_rows()), _findings())
    assert d["verdict"] == "REGRESSED"
    assert len(d["regressed"]) == len(_findings())


def test_evidence_change_on_still_failing_rule():
    old = _findings()
    new = copy.deepcopy(old)
    target = next(f for f in new if f["rule_id"] == "CYB-008")
    target["evidence"].append("DBA granted to NEW_FAKE_USER")  # new grantee appeared
    d = diff_postures(old, new)
    assert "CYB-008" in d["evidence_changed"]
    assert d["verdict"] == "UNCHANGED"  # no new rule failed, but facts moved


def test_rule_set_changes_are_reported():
    old = _findings()
    new = [f for f in old if f["rule_id"] != "CYB-001"]
    d = diff_postures(old, new)
    assert d["rules_removed"] == ["CYB-001"] and d["rules_added"] == []
