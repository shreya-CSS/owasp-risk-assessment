"""Compare two scans by finding fingerprint (stable across scans of the same target)."""
from __future__ import annotations

from modules.models import PRIORITY_LEVELS


def compare_scans(old: list[dict], new: list[dict]) -> dict:
    old_by = {f["fingerprint"]: f for f in old}
    new_by = {f["fingerprint"]: f for f in new}
    introduced = [new_by[k] for k in new_by.keys() - old_by.keys()]
    resolved = [old_by[k] for k in old_by.keys() - new_by.keys()]
    persistent, changed = [], []
    for key in new_by.keys() & old_by.keys():
        before, after = old_by[key], new_by[key]
        persistent.append(after)
        if before["priority"] != after["priority"]:
            direction = ("worse" if PRIORITY_LEVELS.index(after["priority"]) < PRIORITY_LEVELS.index(before["priority"])
                         else "better")
            changed.append({"title": after["title"], "before": before["priority"], "after": after["priority"],
                            "score_before": before["risk_score"], "score_after": after["risk_score"],
                            "direction": direction})
    order = lambda f: (PRIORITY_LEVELS.index(f["priority"]), -f["risk_score"])  # noqa: E731
    return {
        "new": sorted(introduced, key=order),
        "resolved": sorted(resolved, key=order),
        "persistent": sorted(persistent, key=order),
        "priority_changes": changed,
        "max_risk_before": max((f["risk_score"] for f in old), default=0.0),
        "max_risk_after": max((f["risk_score"] for f in new), default=0.0),
    }
