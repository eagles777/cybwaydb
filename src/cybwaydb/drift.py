"""DRIFT DETECTION: diff security posture between two scans.

Answers three questions a DBA asks every scan cycle:
- What got WORSE (newly failing rules)?
- What got FIXED (previously failing, now passing)?
- What changed shape (same rule still failing, but different evidence —
  e.g. a new user picked up the DBA role)?

Pure comparison of two findings.json files. Deterministic, offline, $0.
"""

from __future__ import annotations

import json
from pathlib import Path

from .rules import FAIL


def load_findings(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def diff_postures(old: list[dict], new: list[dict]) -> dict:
    """Compare two scans' findings. Returns regressions, fixes,
    evidence-level changes, and rules added/removed between versions."""
    old_by_id = {f["rule_id"]: f for f in old}
    new_by_id = {f["rule_id"]: f for f in new}
    old_fail = {r for r, f in old_by_id.items() if f["status"] == FAIL}
    new_fail = {r for r, f in new_by_id.items() if f["status"] == FAIL}
    common = set(old_by_id) & set(new_by_id)

    evidence_changed = sorted(
        r for r in (old_fail & new_fail)
        if old_by_id[r]["evidence"] != new_by_id[r]["evidence"]
    )
    return {
        "regressed": sorted((new_fail - old_fail) & common),   # got worse
        "fixed": sorted((old_fail - new_fail) & common),       # got better
        "still_failing": sorted(old_fail & new_fail),
        "evidence_changed": evidence_changed,                  # same rule, new facts
        "rules_added": sorted(set(new_by_id) - set(old_by_id)),
        "rules_removed": sorted(set(old_by_id) - set(new_by_id)),
        "verdict": ("REGRESSED" if (new_fail - old_fail) & common
                    else "IMPROVED" if (old_fail - new_fail) & common
                    else "UNCHANGED"),
    }
