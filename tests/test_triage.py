"""Every high or warning item in the scan has been looked at.

Each must be covered by a finding in the register or by a REVIEWED entry, so
a new issue in a later scan of booking-mobile fails CI until it is triaged.
"""

from __future__ import annotations

from findings import FINDINGS, REVIEWED


def test_every_scanner_item_is_triaged(scorecard: list[dict]) -> None:
    keys = [f.mobsf_title for f in FINDINGS if f.mobsf_title] + list(REVIEWED)
    untriaged = [item["title"] for item in scorecard if not any(k in item["title"] for k in keys)]
    assert not untriaged, "New MobSF items to triage (add a finding or a REVIEWED entry):\n" + "\n".join(
        untriaged
    )


def test_reviewed_entries_still_match_something(scorecard: list[dict]) -> None:
    """A REVIEWED note that no longer matches anything is stale: remove it."""
    stale = [k for k in REVIEWED if not any(k in item["title"] for item in scorecard)]
    assert not stale, f"REVIEWED entries no longer in the scan: {stale}"
