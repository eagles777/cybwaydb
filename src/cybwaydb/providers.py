"""LLM provider abstraction. MOCK by default — no API key, no network, $0.

MockProvider simulates an imperfect LLM auditor deterministically (seeded):
it mostly agrees with the ground-truth rule engine but occasionally misses
a violation or fabricates one. That imperfection is the whole point — it
gives the independent checker and the eval benchmark something real to
catch and measure.

LiveProvider is a stub: it refuses to run without an explicit opt-in flag,
an API key from the environment (.env is gitignored), and a budget ceiling.
The core never imports network libraries.
"""

from __future__ import annotations

import json
import os
import random

from .budget import BudgetCeiling, BudgetExceeded


class MockProvider:
    """Deterministic simulated auditor LLM. cost = $0 always."""

    name = "mock"
    cost_per_call_usd = 0.0

    def __init__(self, seed: int = 0, miss_rate: float = 0.10, fabricate_rate: float = 0.05):
        self.rng = random.Random(seed)
        self.miss_rate = miss_rate
        self.fabricate_rate = fabricate_rate

    def complete(self, prompt: str, ground_truth_findings: list[dict]) -> str:
        """Return strict-JSON findings, imperfectly derived from ground truth."""
        out = []
        for f in ground_truth_findings:
            if f["status"] == "FAIL" and self.rng.random() < self.miss_rate:
                continue  # simulated miss (false negative)
            out.append(f)
        if self.rng.random() < self.fabricate_rate:
            out.append({
                "rule_id": "CYB-999",
                "title": "Fabricated finding (simulated hallucination)",
                "status": "FAIL",
                "severity": "low",
                "references": ["NONE"],
                "evidence": ["hallucinated evidence not present in config"],
                "remediation_sql": "-- no-op",
            })
        return json.dumps(out)


class GeminiProvider:
    """Live Google Gemini provider for the ONE demo run. Guarded four ways:

    1. opt_in=True must be passed explicitly (mock is always the default)
    2. GOOGLE_API_KEY must exist in the environment (gitignored .env / CI secret)
    3. BudgetCeiling.charge() runs BEFORE every network call — over budget
       means the call never happens
    4. Recommended account setup: create the key WITHOUT enabling billing,
       so Google's free tier makes charges impossible at the account level.

    Only config metadata goes into the prompt — never table data, never
    passwords (the synthetic catalog contains none anyway).
    """

    name = "gemini"
    # Default to a model with generous free-tier quota; override via env if needed.
    MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
    # Conservative per-call estimate at published Gemini Flash pricing
    # (a few thousand tokens each way). Real cost is typically lower,
    # and $0 on a no-billing free-tier key.
    EST_COST_PER_CALL_USD = 0.01

    def __init__(self, budget: BudgetCeiling, opt_in: bool = False, transport=None):
        if not opt_in:
            raise RuntimeError("Live mode requires explicit opt_in=True (mock is the default).")
        if not os.environ.get("GOOGLE_API_KEY"):
            raise RuntimeError("Live mode requires GOOGLE_API_KEY in the environment "
                               "(local gitignored .env or CI secret). Refusing to run.")
        self.budget = budget
        self._transport = transport or self._http_post  # injectable for offline tests

    @staticmethod
    def _http_post(url: str, payload: dict) -> dict:
        import json as _json
        import urllib.request
        req = urllib.request.Request(
            url, data=_json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:
            return _json.loads(resp.read().decode("utf-8"))

    def generate(self, prompt: str) -> str:
        # Budget is charged BEFORE the network call. Over budget -> no call.
        self.budget.charge(self.EST_COST_PER_CALL_USD)
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.MODEL}:generateContent?key={os.environ['GOOGLE_API_KEY']}")
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
        }
        data = self._transport(url, payload)
        return data["candidates"][0]["content"]["parts"][0]["text"]


class LiveProvider:
    """Guarded stub for real API calls. Never used by tests or CI."""

    name = "live"

    def __init__(self, budget: BudgetCeiling, opt_in: bool = False):
        if not opt_in:
            raise RuntimeError("Live mode requires explicit opt_in=True (mock is the default).")
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("Live mode requires ANTHROPIC_API_KEY in the environment "
                               "(local gitignored .env or CI secret). Refusing to run.")
        self.budget = budget

    def complete(self, prompt: str, ground_truth_findings=None, estimated_cost_usd: float = 0.05) -> str:
        # Budget is charged BEFORE any call could be made.
        self.budget.charge(estimated_cost_usd)
        raise NotImplementedError("Live API calls are implemented only for the one demo run.")
