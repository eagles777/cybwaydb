# Evidence — Live-Model Benchmark Run

This directory contains the **actual output artifacts** from the one live-model
demo run (Google Gemini `gemini-flash-lite-latest`), scored against the
deterministic rule engine as ground truth. It is committed as verifiable proof
of the published accuracy numbers.

- `live-run/live_benchmark.json` — precision 1.00 / recall 0.94 / F1 0.97 over 3 runs
- `live-run/audit.log.jsonl` — tamper-evident, hash-chained log of the run
  (each entry references the SHA-256 of the previous; any edit breaks the chain —
  run `cybwaydb verify` to check)
- `live-run/manifest.json` — SHA-256 manifest of the run's outputs

No API key, credential, or personal data appears in these files. The benchmark
is reproducible: `cybwaydb benchmark` (mock, free) or `cybwaydb live-demo` (with
your own key). See `BENCHMARKS.md`.
