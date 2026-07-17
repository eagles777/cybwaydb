"""HTML report generator tests. Offline, $0."""

from cybwaydb.engine import run_scan
from cybwaydb.report import build_report_data, render_report_html, write_report
from cybwaydb.synthdb import create_synthetic_db


def _run(tmp_path):
    run_scan(create_synthetic_db(), tmp_path)
    return tmp_path


def test_report_data_is_complete(tmp_path):
    data = build_report_data(_run(tmp_path), mock_runs=5)
    assert data["rules_total"] == 17 and data["failed_count"] == 17
    assert data["chain_ok"] and data["manifest_ok"]
    assert data["redteam_total"] >= 15 and data["injection_hits"]


def test_standalone_html_is_self_contained(tmp_path):
    data = build_report_data(_run(tmp_path), mock_runs=5)
    doc = render_report_html(data, standalone=True)
    assert doc.startswith("<!doctype html>")
    assert "Cybwaydb" in doc and "CYB-006" in doc
    assert "http://" not in doc.replace("http://www.w3", "")  # no external asset URLs
    assert "<script" not in doc                                # static, no JS


def test_embed_variant_has_no_html_wrapper(tmp_path):
    data = build_report_data(_run(tmp_path), mock_runs=5)
    embed = render_report_html(data, standalone=False)
    assert "<!doctype" not in embed and "<html" not in embed
    assert embed.strip().startswith("<style>")


def test_write_report_file(tmp_path):
    run_dir = _run(tmp_path)
    out = write_report(run_dir, tmp_path / "report.html")
    assert out.exists() and out.stat().st_size > 2000


def test_report_includes_live_numbers_when_present(tmp_path):
    import json
    run_dir = _run(tmp_path)
    live = tmp_path / "live_benchmark.json"
    live.write_text(json.dumps({"model": "gemini-flash-lite-latest",
                                "precision": 1.0, "recall": 0.94, "f1": 0.97}))
    data = build_report_data(run_dir, live_benchmark_path=live, mock_runs=5)
    assert data["live"]["precision"] == 1.0
    doc = render_report_html(data)
    assert "gemini-flash-lite-latest" in doc and "live precision" in doc
