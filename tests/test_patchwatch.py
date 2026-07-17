"""PATCH-WATCH tests: Oracle quarterly CPU cycle math + the CYB-017 rule."""

from datetime import date

import pytest

from cybwaydb.patchwatch import cpu_release_date, current_cpu_cycle, next_cpu_cycle, patch_status
from cybwaydb.rules import run_all_rules
from cybwaydb.synthdb import create_synthetic_db, compliant_rows


def test_cpu_release_date_is_tuesday_closest_to_17th():
    # Known/derivable dates: Tuesday closest to the 17th
    assert cpu_release_date(2026, 1) == date(2026, 1, 20)   # 17th is Sat -> Tue 20th
    assert cpu_release_date(2026, 4) == date(2026, 4, 14)   # 17th is Fri -> Tue 14th
    assert cpu_release_date(2026, 7) == date(2026, 7, 14)
    assert cpu_release_date(2025, 10) == date(2025, 10, 21) # 17th is Fri... verify Tuesday
    for y in range(2024, 2028):
        for m in (1, 4, 7, 10):
            d = cpu_release_date(y, m)
            assert d.weekday() == 1                          # Tuesday
            # near the 17th (published overrides can be up to 4 days out)
            assert abs((d - date(y, m, 17)).days) <= 4


def test_cpu_release_date_rejects_non_cpu_month():
    with pytest.raises(ValueError):
        cpu_release_date(2026, 2)


def test_current_and_next_cycle():
    as_of = date(2026, 7, 17)
    assert current_cpu_cycle(as_of) == date(2026, 7, 14)
    assert next_cpu_cycle(as_of) == date(2026, 10, 20)
    # day before July 2026 CPU -> still on April cycle
    assert current_cpu_cycle(date(2026, 7, 13)) == date(2026, 4, 14)
    # year boundary: early January before the Jan CPU -> previous October
    assert current_cpu_cycle(date(2026, 1, 5)) == date(2025, 10, 21)


def test_patch_status_states():
    as_of = date(2026, 7, 17)
    assert patch_status(date(2026, 7, 14), as_of)["state"] == "CURRENT"
    behind = patch_status(date(2025, 10, 21), as_of)
    assert behind["state"] == "BEHIND"
    assert behind["cycles_behind"] == 3                      # Jan, Apr, Jul 2026 missed
    unknown = patch_status(None, as_of)
    assert unknown["state"] == "UNKNOWN"


def test_cyb017_fails_on_baseline_and_passes_on_compliant():
    baseline = {f.rule_id: f for f in run_all_rules(create_synthetic_db())}
    assert baseline["CYB-017"].status == "FAIL"
    assert any("3 cycle(s) behind" in e for e in baseline["CYB-017"].evidence)
    compliant = {f.rule_id: f for f in run_all_rules(create_synthetic_db(rows=compliant_rows()))}
    assert compliant["CYB-017"].status == "PASS"
