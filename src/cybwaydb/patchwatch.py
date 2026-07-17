"""PATCH-WATCH: Oracle Critical Patch Update (CPU) cycle awareness.

Oracle releases CPUs quarterly, on the Tuesday closest to the 17th of
January, April, July, and October. Those dates are facts; we compute and
state them and link to Oracle's public advisory page — we never copy
Oracle text. See LEGAL.md.

Advisory calendar: https://www.oracle.com/security-alerts/
"""

from __future__ import annotations

from datetime import date, timedelta

CPU_MONTHS = (1, 4, 7, 10)
ORACLE_ADVISORY_URL = "https://www.oracle.com/security-alerts/"

# Oracle's published calendar occasionally deviates from the
# closest-Tuesday heuristic; published dates (facts) take precedence.
KNOWN_CPU_DATES = {
    (2025, 10): date(2025, 10, 21),
}


def cpu_release_date(year: int, month: int) -> date:
    """CPU release date: Oracle's published date if known, else the
    Tuesday closest to the 17th of the CPU month."""
    if month not in CPU_MONTHS:
        raise ValueError(f"{month} is not a CPU month {CPU_MONTHS}")
    if (year, month) in KNOWN_CPU_DATES:
        return KNOWN_CPU_DATES[(year, month)]
    anchor = date(year, month, 17)
    offset = (anchor.weekday() - 1) % 7          # days back to Tuesday
    prev_tue = anchor - timedelta(days=offset)
    next_tue = prev_tue + timedelta(days=7)
    return prev_tue if (anchor - prev_tue) <= (next_tue - anchor) else next_tue


def current_cpu_cycle(as_of: date) -> date:
    """Most recent CPU release date on or before as_of."""
    candidates = [cpu_release_date(y, m)
                  for y in (as_of.year - 1, as_of.year)
                  for m in CPU_MONTHS]
    return max(d for d in candidates if d <= as_of)


def next_cpu_cycle(as_of: date) -> date:
    candidates = [cpu_release_date(y, m)
                  for y in (as_of.year, as_of.year + 1)
                  for m in CPU_MONTHS]
    return min(d for d in candidates if d > as_of)


def patch_status(last_patch_applied: date | None, as_of: date) -> dict:
    """Classify a database's CPU patch posture as of a given date."""
    cycle = current_cpu_cycle(as_of)
    if last_patch_applied is None:
        state, lag = "UNKNOWN", None
    elif last_patch_applied >= cycle:
        state, lag = "CURRENT", 0
    else:
        # count how many cycles behind
        lag, probe = 0, as_of
        while current_cpu_cycle(probe) > last_patch_applied:
            lag += 1
            probe = current_cpu_cycle(probe) - timedelta(days=1)
        state = "BEHIND"
    return {
        "state": state,                              # CURRENT / BEHIND / UNKNOWN
        "cycles_behind": lag,
        "current_cycle": cycle.isoformat(),
        "next_cycle": next_cpu_cycle(as_of).isoformat(),
        "last_patch_applied": last_patch_applied.isoformat() if last_patch_applied else None,
        "advisory": ORACLE_ADVISORY_URL,
    }
