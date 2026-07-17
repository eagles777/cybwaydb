"""Live-demo guardrail tests. ALL OFFLINE — the network layer is replaced
by a fake transport; no real API call is ever made in tests or CI."""

import json

import pytest

from cybwaydb.budget import BudgetCeiling, BudgetExceeded
from cybwaydb.livedemo import build_prompt, config_snapshot, run_live_demo
from cybwaydb.providers import GeminiProvider
from cybwaydb.rules import run_all_rules, FAIL
from cybwaydb.synthdb import create_synthetic_db


def fake_transport_factory(findings_json: str, calls: list):
    def fake_transport(url, payload):
        calls.append({"url_has_key": "key=" in url, "payload": payload})
        return {"candidates": [{"content": {"parts": [{"text": findings_json}]}}]}
    return fake_transport


def perfect_findings_json():
    return json.dumps([f.to_dict() for f in run_all_rules(create_synthetic_db())
                       if f.status == FAIL])


def test_gemini_refuses_without_opt_in_or_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="opt_in"):
        GeminiProvider(BudgetCeiling(2.0))
    with pytest.raises(RuntimeError, match="GOOGLE_API_KEY"):
        GeminiProvider(BudgetCeiling(2.0), opt_in=True)


def test_budget_charged_before_call_and_blocks_overrun(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    calls = []
    provider = GeminiProvider(BudgetCeiling(0.025), opt_in=True,
                              transport=fake_transport_factory("[]", calls))
    provider.generate("p")
    provider.generate("p")
    with pytest.raises(BudgetExceeded):
        provider.generate("p")          # third call would exceed $0.025
    assert len(calls) == 2              # the blocked call NEVER hit the network


def test_prompt_contains_config_but_never_table_data():
    conn = create_synthetic_db()
    prompt = build_prompt(conn)
    assert "dba_users" in prompt and "CYB-001" in prompt
    # the canary table (stand-in for application data) must NOT be sent
    assert "EMPLOYEES_FAKE" not in config_snapshot(conn)


def test_live_demo_end_to_end_with_fake_transport(monkeypatch, tmp_path):
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    calls = []
    result = run_live_demo(tmp_path, budget_usd=2.00, n_runs=3,
                           transport=fake_transport_factory(perfect_findings_json(), calls))
    assert result["precision"] == 1.0 and result["recall"] == 1.0
    assert result["spent_usd_estimate"] <= 2.00
    assert len(calls) == 3
    assert (tmp_path / "live_benchmark.json").exists()
    from cybwaydb.auditlog import AuditLog
    ok, msg = AuditLog(tmp_path / "audit.log.jsonl").verify_chain()
    assert ok, msg


def test_live_demo_stops_mid_run_when_budget_exhausted(monkeypatch, tmp_path):
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    calls = []
    with pytest.raises(BudgetExceeded):
        run_live_demo(tmp_path, budget_usd=0.015, n_runs=5,
                      transport=fake_transport_factory(perfect_findings_json(), calls))
    assert len(calls) == 1              # second call blocked before the network


def test_cli_refuses_without_confirmation_flag(capsys):
    from cybwaydb.cli import main
    assert main(["live-demo"]) == 1
    assert "Refusing" in capsys.readouterr().out


def test_cli_refuses_budget_above_two_dollars(capsys):
    from cybwaydb.cli import main
    assert main(["live-demo", "--i-understand-costs", "--budget", "5"]) == 1
    assert "$2.00" in capsys.readouterr().out
