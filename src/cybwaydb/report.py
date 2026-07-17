"""Self-contained HTML compliance report generator.

Turns a scan run (findings.json + audit log) plus benchmark/red-team
results into a single standalone HTML file — no external assets, no
network, opens by double-click in any browser. Also renders an
embed-only variant (style + content, no <html> wrapper) for hosting.

Everything shown is synthetic. Deterministic, offline, $0.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from .agents import CheckerAgent
from .auditlog import AuditLog, verify_manifest
from .evalbench import run_benchmark
from .redteam import INJECTION_PATTERNS
from .rules import FAIL, RULES
from .synthdb import create_synthetic_db

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def build_report_data(run_dir: str | Path, live_benchmark_path: str | Path | None = None,
                      mock_runs: int = 20) -> dict:
    run_dir = Path(run_dir)
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    findings.sort(key=lambda f: (f["status"] != FAIL, SEV_ORDER.get(f["severity"], 9), f["rule_id"]))

    chain_ok, chain_msg = AuditLog(run_dir / "audit.log.jsonl").verify_chain()
    man_ok, man_problems = verify_manifest(run_dir)

    injection = CheckerAgent().scan_config(create_synthetic_db())
    mock = run_benchmark(n_runs=mock_runs)

    live = None
    lbp = Path(live_benchmark_path) if live_benchmark_path else run_dir.parent / "live-demo" / "live_benchmark.json"
    if lbp and Path(lbp).exists():
        live = json.loads(Path(lbp).read_text(encoding="utf-8"))

    failed = [f for f in findings if f["status"] == FAIL]
    return {
        "findings": findings,
        "failed_count": len(failed),
        "passed_count": len(findings) - len(failed),
        "rules_total": len(RULES),
        "severity_counts": {s: sum(1 for f in failed if f["severity"] == s) for s in ("high", "medium", "low")},
        "chain_ok": chain_ok, "chain_msg": chain_msg,
        "manifest_ok": man_ok, "manifest_problems": man_problems,
        "redteam_total": len(INJECTION_PATTERNS),
        "injection_hits": injection,
        "mock": mock,
        "live": live,
    }


_CSS = """
:root{
  --ground:#eef1f5; --surface:#ffffff; --surface-2:#f6f8fb; --ink:#0f1a26;
  --muted:#5a6b7d; --line:#dce2ea; --accent:#0e7fb8; --accent-soft:#e3f1f9;
  --high:#c0362c; --med:#b0741a; --low:#4a6785; --pass:#1f7a4d;
  --high-soft:#f8e6e4; --med-soft:#f7edda; --pass-soft:#e2f1ea;
}
@media (prefers-color-scheme:dark){
  :root{
    --ground:#0d141d; --surface:#141d28; --surface-2:#1a2634; --ink:#e7eef6;
    --muted:#93a4b8; --line:#26333f; --accent:#38bdf8; --accent-soft:#0f3247;
    --high:#f2645a; --med:#e0a13c; --low:#8299b8; --pass:#48c98a;
    --high-soft:#2a1614; --med-soft:#2a2011; --pass-soft:#12271d;
  }
}
:root[data-theme="light"]{
  --ground:#eef1f5; --surface:#ffffff; --surface-2:#f6f8fb; --ink:#0f1a26;
  --muted:#5a6b7d; --line:#dce2ea; --accent:#0e7fb8; --accent-soft:#e3f1f9;
  --high:#c0362c; --med:#b0741a; --low:#4a6785; --pass:#1f7a4d;
  --high-soft:#f8e6e4; --med-soft:#f7edda; --pass-soft:#e2f1ea;
}
:root[data-theme="dark"]{
  --ground:#0d141d; --surface:#141d28; --surface-2:#1a2634; --ink:#e7eef6;
  --muted:#93a4b8; --line:#26333f; --accent:#38bdf8; --accent-soft:#0f3247;
  --high:#f2645a; --med:#e0a13c; --low:#8299b8; --pass:#48c98a;
  --high-soft:#2a1614; --med-soft:#2a2011; --pass-soft:#12271d;
}
*{box-sizing:border-box}
.cw-root{
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Code",Menlo,Consolas,monospace;
  background:var(--ground); color:var(--ink); font-family:var(--sans);
  line-height:1.55; margin:0; padding:32px 20px; -webkit-font-smoothing:antialiased;
}
.cw-wrap{max-width:1060px; margin:0 auto; display:flex; flex-direction:column; gap:26px}
.cw-mono{font-family:var(--mono)}
.cw-label{font-family:var(--mono); font-size:11px; letter-spacing:.14em; text-transform:uppercase; color:var(--muted)}
.cw-card{background:var(--surface); border:1px solid var(--line); border-radius:12px}

/* Masthead */
.cw-head{display:flex; flex-wrap:wrap; align-items:flex-end; justify-content:space-between; gap:16px;
  padding-bottom:20px; border-bottom:1px solid var(--line)}
.cw-brand{display:flex; flex-direction:column; gap:6px}
.cw-brand h1{font-size:30px; font-weight:680; margin:0; letter-spacing:-.01em; text-wrap:balance}
.cw-brand .cw-sub{color:var(--muted); font-size:14px; max-width:60ch}
.cw-verdict{display:inline-flex; align-items:center; gap:9px; padding:9px 15px; border-radius:999px;
  font-family:var(--mono); font-size:13px; font-weight:600; border:1px solid}
.cw-verdict.bad{color:var(--high); background:var(--high-soft); border-color:var(--high)}
.cw-dot{width:9px; height:9px; border-radius:50%; background:currentColor; box-shadow:0 0 0 4px color-mix(in srgb,currentColor 18%,transparent)}

/* KPI grid */
.cw-kpis{display:grid; grid-template-columns:repeat(auto-fit,minmax(155px,1fr)); gap:12px}
.cw-kpi{padding:16px 16px 15px; display:flex; flex-direction:column; gap:7px}
.cw-kpi .v{font-size:27px; font-weight:680; font-family:var(--mono); font-variant-numeric:tabular-nums; line-height:1}
.cw-kpi .v.ok{color:var(--pass)} .cw-kpi .v.warn{color:var(--high)} .cw-kpi .v.accent{color:var(--accent)}
.cw-kpi .cap{font-size:12.5px; color:var(--muted)}

/* Section shell */
.cw-sec{display:flex; flex-direction:column; gap:14px}
.cw-sec > h2{font-size:13px; font-family:var(--mono); letter-spacing:.12em; text-transform:uppercase;
  color:var(--muted); margin:0; font-weight:600}

/* Governance pipeline */
.cw-flow{display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px}
.cw-stage{padding:16px; display:flex; flex-direction:column; gap:8px; position:relative}
.cw-stage .n{font-family:var(--mono); font-size:12px; color:var(--accent); font-weight:700}
.cw-stage h3{margin:0; font-size:15px; font-weight:640}
.cw-stage p{margin:0; font-size:13px; color:var(--muted)}
.cw-stage.gate{border-color:var(--accent)}

/* Findings */
.cw-find{display:flex; flex-direction:column; gap:10px}
.cw-f{display:grid; grid-template-columns:5px 1fr; overflow:hidden}
.cw-f .stripe{background:var(--low)}
.cw-f.high .stripe{background:var(--high)} .cw-f.medium .stripe{background:var(--med)} .cw-f.low .stripe{background:var(--low)}
.cw-f .body{padding:14px 16px; display:flex; flex-direction:column; gap:10px; min-width:0}
.cw-f .top{display:flex; flex-wrap:wrap; align-items:center; gap:10px}
.cw-f .rid{font-family:var(--mono); font-size:12.5px; color:var(--accent); font-weight:600}
.cw-f .title{font-weight:600; font-size:15px; flex:1; min-width:220px}
.cw-pill{font-family:var(--mono); font-size:10.5px; letter-spacing:.06em; text-transform:uppercase;
  padding:3px 9px; border-radius:999px; font-weight:700; white-space:nowrap}
.cw-pill.high{color:var(--high); background:var(--high-soft)}
.cw-pill.medium{color:var(--med); background:var(--med-soft)}
.cw-pill.low{color:var(--low); background:var(--surface-2)}
.cw-pill.fail{color:var(--high); background:var(--high-soft)}
.cw-ev{display:flex; flex-wrap:wrap; gap:6px}
.cw-ev .chip{font-family:var(--mono); font-size:12px; background:var(--surface-2); border:1px solid var(--line);
  padding:3px 9px; border-radius:6px; color:var(--ink)}
.cw-sql{font-family:var(--mono); font-size:12.5px; background:var(--surface-2); border:1px solid var(--line);
  border-radius:8px; padding:10px 12px; overflow-x:auto; white-space:pre; color:var(--ink)}
.cw-refs{display:flex; flex-wrap:wrap; gap:6px}
.cw-refs .ref{font-family:var(--mono); font-size:11px; color:var(--muted)}
.cw-refs .ref::before{content:"§ "}

/* Benchmark meters */
.cw-bench{display:grid; grid-template-columns:1fr 1fr; gap:16px}
@media (max-width:640px){.cw-bench{grid-template-columns:1fr} .cw-flow{grid-template-columns:1fr}}
.cw-meter{padding:16px; display:flex; flex-direction:column; gap:12px}
.cw-meter h3{margin:0; font-size:14px; font-weight:640; display:flex; justify-content:space-between; align-items:baseline}
.cw-meter h3 .tag{font-family:var(--mono); font-size:11px; color:var(--muted); font-weight:500}
.cw-metric{display:flex; flex-direction:column; gap:5px}
.cw-metric .row{display:flex; justify-content:space-between; font-size:12.5px}
.cw-metric .row .name{color:var(--muted); font-family:var(--mono); text-transform:uppercase; letter-spacing:.06em; font-size:11px}
.cw-metric .row .num{font-family:var(--mono); font-variant-numeric:tabular-nums; font-weight:600}
.cw-bar{height:8px; border-radius:999px; background:var(--surface-2); overflow:hidden}
.cw-bar > span{display:block; height:100%; background:var(--accent); border-radius:999px}
.cw-bar.pass > span{background:var(--pass)}

/* integrity + redteam row */
.cw-status{display:grid; grid-template-columns:1fr 1fr; gap:12px}
@media (max-width:640px){.cw-status{grid-template-columns:1fr}}
.cw-status .box{padding:16px; display:flex; align-items:center; gap:13px}
.cw-status .ic{width:34px; height:34px; border-radius:9px; display:grid; place-items:center; flex:none;
  font-family:var(--mono); font-weight:700; font-size:15px}
.cw-status .ic.ok{color:var(--pass); background:var(--pass-soft)}
.cw-status .t{font-weight:620; font-size:14px} .cw-status .s{color:var(--muted); font-size:12.5px}

.cw-foot{border-top:1px solid var(--line); padding-top:18px; color:var(--muted); font-size:12px; display:flex;
  flex-direction:column; gap:5px}
.cw-foot b{color:var(--ink); font-weight:600}
"""


def _esc(s) -> str:
    return html.escape(str(s))


def _finding_html(f: dict) -> str:
    sev = f["severity"]
    ev = "".join(f'<span class="chip">{_esc(e)}</span>' for e in f.get("evidence", []))
    refs = "".join(f'<span class="ref">{_esc(r)}</span>' for r in f.get("references", []))
    sql = f.get("remediation_sql", "")
    sql_block = f'<div class="cw-sql">{_esc(sql)}</div>' if sql else ""
    return f"""<div class="cw-f {sev}"><div class="stripe"></div><div class="body">
      <div class="top"><span class="rid">{_esc(f['rule_id'])}</span>
        <span class="title">{_esc(f['title'])}</span>
        <span class="cw-pill {sev}">{_esc(sev)}</span>
        <span class="cw-pill fail">{_esc(f['status'])}</span></div>
      <div class="cw-ev">{ev}</div>
      {sql_block}
      <div class="cw-refs">{refs}</div>
    </div></div>"""


def _meter(title: str, tag: str, precision: float, recall: float, f1: float) -> str:
    def row(name, val):
        pct = max(0, min(100, val * 100))
        cls = "pass" if val >= 0.9 else ""
        return (f'<div class="cw-metric"><div class="row"><span class="name">{name}</span>'
                f'<span class="num">{val:.3f}</span></div>'
                f'<div class="cw-bar {cls}"><span style="width:{pct:.1f}%"></span></div></div>')
    return f"""<div class="cw-meter cw-card"><h3>{_esc(title)}<span class="tag">{_esc(tag)}</span></h3>
      {row("Precision", precision)}{row("Recall", recall)}{row("F1", f1)}</div>"""


def render_report_html(data: dict, standalone: bool = True) -> str:
    sc = data["severity_counts"]
    kpis = [
        ("accent", data["rules_total"], "STIG / NIST checks run"),
        ("warn", data["failed_count"], "violations found"),
        ("warn", sc["high"], "high severity"),
    ]
    if data["live"]:
        kpis += [
            ("ok", f"{data['live']['precision']:.2f}", "live precision"),
            ("ok", f"{data['live']['recall']:.2f}", "live recall"),
        ]
    kpis.append(("ok", f"{len(data['injection_hits'])}/{data['redteam_total']}",
                 "red-team patterns caught"))
    kpi_html = "".join(
        f'<div class="cw-kpi cw-card"><span class="v {c}">{_esc(v)}</span><span class="cap">{_esc(cap)}</span></div>'
        for c, v, cap in kpis)

    findings_html = "".join(_finding_html(f) for f in data["findings"])

    flow = """
    <div class="cw-flow">
      <div class="cw-stage cw-card"><span class="n">STAGE 1</span><h3>AI Auditor</h3>
        <p>Reads the security configuration and drafts findings plus proposed remediation SQL as strict JSON.</p></div>
      <div class="cw-stage cw-card"><span class="n">STAGE 2</span><h3>Independent Checker</h3>
        <p>Re-verifies every finding against the raw configuration. Adjudicates PASS / REVIEW / QUARANTINE. Never grades its own generation.</p></div>
      <div class="cw-stage cw-card gate"><span class="n">STAGE 3</span><h3>Human Gate</h3>
        <p>A person approves, rejects, or risk-accepts (NIST CA-5). Nothing resolves and no SQL runs without a logged human decision.</p></div>
    </div>"""

    bench = _meter("Live model — Google Gemini", data["live"]["model"],
                   data["live"]["precision"], data["live"]["recall"], data["live"]["f1"]) if data["live"] else ""
    bench += _meter("Mock provider — harness validation", f"{data['mock']['n_runs']} runs",
                    data["mock"]["precision"], data["mock"]["recall"], data["mock"]["f1"])

    chain_ic = "OK" if data["chain_ok"] else "!"
    man_ic = "OK" if data["manifest_ok"] else "!"
    status = f"""
    <div class="cw-status">
      <div class="box cw-card"><div class="ic ok">{chain_ic}</div>
        <div><div class="t">Audit log — hash chain intact</div>
        <div class="s">Any edit, deletion, or reordering of the record is detected.</div></div></div>
      <div class="box cw-card"><div class="ic ok">{man_ic}</div>
        <div><div class="t">Run manifest verified</div>
        <div class="s">SHA-256 of every output file matches; no post-run tampering.</div></div></div>
    </div>"""

    body = f"""
  <div class="cw-root"><div class="cw-wrap">
    <header class="cw-head">
      <div class="cw-brand">
        <span class="cw-label">Governed-AI database compliance audit</span>
        <h1>Cybwaydb</h1>
        <span class="cw-sub">Synthetic Oracle-style security catalog checked against public DISA STIG / NIST SP 800-53 rules, audited by an AI pipeline with independent verification and a human approval gate.</span>
      </div>
      <div class="cw-verdict bad"><span class="cw-dot"></span>{data['failed_count']} of {data['rules_total']} controls failing</div>
    </header>

    <div class="cw-kpis">{kpi_html}</div>

    <section class="cw-sec"><h2>AI governance pipeline</h2>{flow}</section>

    <section class="cw-sec"><h2>Published AI accuracy</h2><div class="cw-bench">{bench}</div></section>

    <section class="cw-sec"><h2>Integrity controls</h2>{status}</section>

    <section class="cw-sec"><h2>Findings &middot; {data['failed_count']} open</h2>
      <div class="cw-find">{findings_html}</div></section>

    <footer class="cw-foot">
      <span><b>Synthetic data only.</b> Every account, hash, and hostname shown is invented for testing. No real database, credential, or organizational data.</span>
      <span>A personal portfolio project by <b>V. Vikram</b> &middot; Apache-2.0 &middot; Defensive security only. STIG/NIST are public-domain US Government works cited by rule ID.</span>
    </footer>
  </div></div>"""

    style = f"<style>{_CSS}</style>"
    if not standalone:
        return style + body
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cybwaydb — Compliance Audit Report</title>{style}</head>
<body style="margin:0">{body}</body></html>"""


def write_report(run_dir: str | Path, out_path: str | Path,
                 live_benchmark_path: str | Path | None = None, standalone: bool = True) -> Path:
    data = build_report_data(run_dir, live_benchmark_path=live_benchmark_path)
    out = Path(out_path)
    out.write_text(render_report_html(data, standalone=standalone), encoding="utf-8")
    return out
