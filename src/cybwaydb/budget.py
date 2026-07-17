"""Code-enforced budget ceiling for any paid LLM call.

The ceiling is charged BEFORE a call is made; exceeding it raises and the
call never happens. dry_run() lets a human see projected cost first.
"""

from __future__ import annotations


class BudgetExceeded(RuntimeError):
    pass


class BudgetCeiling:
    def __init__(self, max_usd: float):
        if max_usd < 0:
            raise ValueError("budget must be >= 0")
        self.max_usd = max_usd
        self.spent_usd = 0.0

    def dry_run(self, estimated_cost_usd: float) -> dict:
        projected = self.spent_usd + estimated_cost_usd
        return {
            "estimated_cost_usd": estimated_cost_usd,
            "spent_usd": self.spent_usd,
            "projected_usd": projected,
            "ceiling_usd": self.max_usd,
            "would_exceed": projected > self.max_usd,
        }

    def charge(self, estimated_cost_usd: float) -> None:
        if self.dry_run(estimated_cost_usd)["would_exceed"]:
            raise BudgetExceeded(
                f"charge of ${estimated_cost_usd:.4f} would exceed ceiling "
                f"${self.max_usd:.2f} (spent ${self.spent_usd:.4f})"
            )
        self.spent_usd += estimated_cost_usd
