"""Tests for feeding your own SQLite catalog: init-db + scan --db."""

import json
import sqlite3

from cybwaydb.cli import main


def test_init_db_then_scan_reflects_edits(tmp_path, capsys):
    db = tmp_path / "mydb.sqlite"
    assert main(["init-db", "--out", str(db)]) == 0
    assert db.exists()

    # edit the catalog: lock SCOTT (one of the two open demo accounts)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE dba_users SET account_status='LOCKED' WHERE username='SCOTT'")
    conn.commit()
    conn.close()

    out = tmp_path / "run"
    assert main(["scan", "--db", str(db), "--out", str(out)]) == 0
    findings = json.loads((out / "findings.json").read_text())
    cyb006 = next(f for f in findings if f["rule_id"] == "CYB-006")
    assert cyb006["evidence"] == ["DBSNMP is OPEN"]  # SCOTT no longer flagged


def test_scan_without_db_uses_builtin_synthetic(tmp_path):
    out = tmp_path / "run"
    assert main(["scan", "--out", str(out)]) == 0
    summary = json.loads((out / "findings.json").read_text())
    assert len(summary) == 17
