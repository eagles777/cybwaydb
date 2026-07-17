"""EVAL BENCHMARK: measure the AI auditor's precision/recall against
ground truth over N seeded runs. Headline metric of the project.

Ground truth = the deterministic rule engine on the same raw config.
Deterministic (seeded), offline, $0.
"""

from __future__ import annotations

from .agents import AuditorAgent
from .providers import MockProvider
from .rules import run_all_rules, FAIL
from .synthdb import create_synthetic_db


def run_benchmark(n_runs: int = 50, base_seed: int = 42, provider_factory=None) -> dict:
    """Run the auditor n_runs times (fresh seed each run) and score it."""
    if provider_factory is None:
        provider_factory = lambda seed: MockProvider(seed=seed)

    conn = create_synthetic_db()
    truth = {f.rule_id for f in run_all_rules(conn) if f.status == FAIL}

    tp = fp = fn = 0
    per_run = []
    for i in range(n_runs):
        auditor = AuditorAgent(provider_factory(base_seed + i))
        reported = {f["rule_id"] for f in auditor.audit(conn)}
        run_tp = len(reported & truth)
        run_fp = len(reported - truth)
        run_fn = len(truth - reported)
        tp, fp, fn = tp + run_tp, fp + run_fp, fn + run_fn
        per_run.append({"run": i, "tp": run_tp, "fp": run_fp, "fn": run_fn})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "n_runs": n_runs,
        "ground_truth_violations": len(truth),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "provider": "mock",
        "cost_usd": 0,
        "per_run": per_run,
    }
