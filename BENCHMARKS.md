# BENCHMARKS.md — Published AI Accuracy Metrics

Cybwaydb measures its own AI auditor against deterministic ground truth
(the rule engine on the same raw synthetic config). Numbers are reproducible.

## Live model — Google Gemini (`gemini-flash-lite-latest`)

One budget-capped demo run, 3 iterations, synthetic non-compliant database
(17 seeded violations). Config metadata only sent to the model; no table
data, no credentials.

| Metric | Value |
|---|---|
| Precision | **1.000** |
| Recall | **0.941** |
| F1 | **0.970** |
| Runs | 3 |
| True positives / run | 16 of 17 |
| False positives / run | 0 |
| Independent-checker verified | 16 / 16 reported findings per run |
| Cost | ~$0.03 estimated ceiling charge; $0.00 actual (free tier) |
| Budget ceiling enforced | $2.00 (hard cap, charged before every call) |

Interpretation: the live model found 16 of 17 real violations every run
with zero false positives; the one consistent miss is a recall gap worth a
follow-up prompt refinement. The independent checker verified every
reported finding against the raw configuration.

## Mock provider (harness validation, deterministic, $0)

Seeded simulated auditor (10% miss / 5% fabricate), 50 runs — used in CI
to validate the measurement harness at zero cost.

| Metric | Value |
|---|---|
| Precision | 0.9987 |
| Recall | 0.8965 |
| F1 | 0.9448 |
| Runs | 50 |

## Reproduce

```bash
# Mock (free, offline):
cybwaydb benchmark --runs 50

# Live (requires GOOGLE_API_KEY in env; free-tier key recommended):
cybwaydb live-demo --i-understand-costs --budget 2.00 --runs 3
```
