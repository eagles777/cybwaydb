"""Core test suite: synthetic DB, rule engine, tamper-evident audit log,
manifest, and repo-hygiene controls. All offline, $0."""

import json
from pathlib import Path

import pytest

from cybwaydb.auditlog import AuditLog, write_manifest, verify_manifest
from cybwaydb.controls import policy_lint, secret_scan
from cybwaydb.engine import run_scan
from cybwaydb.rules import RULES, run_all_rules, FAIL, PASS
from cybwaydb.synthdb import create_synthetic_db, compliant_rows


# ---------- synthetic DB ----------

def test_synthetic_db_has_expected_views():
    conn = create_synthetic_db()
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"dba_users", "dba_profiles", "dba_role_privs",
            "dba_sys_privs", "v_parameter", "dba_stmt_audit_opts"} <= tables


def test_synthetic_data_is_fake_only():
    conn = create_synthetic_db()
    users = [r[0] for r in conn.execute("SELECT username FROM dba_users")]
    # Non-Oracle-default accounts must be clearly synthetic.
    oracle_defaults = {"SYS", "SYSTEM", "SCOTT", "DBSNMP", "OUTLN"}
    for u in users:
        assert u in oracle_defaults or "FAKE" in u


# ---------- rule engine ----------

def test_rule_count_in_scope():
    assert 12 <= len(RULES) <= 20


def test_noncompliant_baseline_fails_every_rule():
    conn = create_synthetic_db()
    findings = run_all_rules(conn)
    assert all(f.status == FAIL for f in findings), \
        [f.rule_id for f in findings if f.status != FAIL]


def test_compliant_db_passes_every_rule():
    conn = create_synthetic_db(rows=compliant_rows())
    findings = run_all_rules(conn)
    assert all(f.status == PASS for f in findings), \
        [(f.rule_id, f.evidence) for f in findings if f.status != PASS]


def test_findings_carry_citations_and_remediation():
    findings = run_all_rules(create_synthetic_db())
    for f in findings:
        assert f.references, f.rule_id
        assert any("NIST" in r or "STIG" in r for r in f.references), f.rule_id
        if f.status == FAIL:
            assert f.remediation_sql, f.rule_id


def test_rule_ids_unique():
    ids = [f.rule_id for f in run_all_rules(create_synthetic_db())]
    assert len(ids) == len(set(ids))


# ---------- audit log: hash chain + tamper detection ----------

def test_audit_chain_verifies_when_intact(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.append("event", {"i": i})
    ok, msg = log.verify_chain()
    assert ok, msg


def test_log_tamper_detection_modified_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.append("event", {"i": i})
    lines = path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["detail"]["i"] = 999  # attacker edits a historical entry
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    ok, msg = log.verify_chain()
    assert not ok and "entry 3" in msg


def test_log_tamper_detection_deleted_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.append("event", {"i": i})
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, _ = log.verify_chain()
    assert not ok


def test_log_tamper_detection_reordered_entries(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.append("event", {"i": i})
    lines = path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, _ = log.verify_chain()
    assert not ok


# ---------- manifest ----------

def test_manifest_roundtrip_and_tamper_detection(tmp_path):
    (tmp_path / "findings.json").write_text('{"a": 1}')
    write_manifest(tmp_path)
    ok, problems = verify_manifest(tmp_path)
    assert ok, problems
    (tmp_path / "findings.json").write_text('{"a": 2}')  # tamper
    ok, problems = verify_manifest(tmp_path)
    assert not ok and "findings.json" in problems[0]


# ---------- engine end-to-end ----------

def test_run_scan_end_to_end(tmp_path):
    conn = create_synthetic_db()
    summary = run_scan(conn, tmp_path)
    assert summary["mode"] == "mock" and summary["cost_usd"] == 0
    assert summary["failed"] == summary["total"] == len(RULES)
    assert (tmp_path / "findings.json").exists()
    ok, msg = AuditLog(tmp_path / "audit.log.jsonl").verify_chain()
    assert ok, msg
    ok, problems = verify_manifest(tmp_path)
    assert ok, problems


# ---------- controls ----------

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_secret_scan_detects_planted_secret(tmp_path):
    bad = tmp_path / "config.py"
    planted = 'API_KEY = "sk-ant-' + "abcdefghijklmnop1234" + '"\n'  # split so repo scan skips it
    bad.write_text(planted)
    hits = secret_scan(tmp_path)
    assert hits and hits[0]["pattern"] == "anthropic_api_key"


def test_secret_scan_repo_is_clean():
    assert secret_scan(REPO_ROOT) == []


def test_policy_lint_repo_is_clean():
    assert policy_lint(REPO_ROOT) == []


def test_policy_lint_detects_unignored_env(tmp_path):
    (tmp_path / ".env").write_text("X=1\n")
    violations = policy_lint(tmp_path)
    assert violations and ".env" in violations[0]["term"]
