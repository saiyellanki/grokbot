"""Adaptive discovery — missing CMDB is not a stop for read workflows."""

from __future__ import annotations

from typing import Any


def _confidence(resource: dict[str, Any], ci: dict[str, Any] | None) -> float:
    if ci is None:
        return 0.40
    if not ci.get("tags_complete", False):
        return 0.72
    return 0.95


def classify(resource: dict[str, Any], ci: dict[str, Any] | None) -> dict[str, Any]:
    if resource.get("type") == "shadow_saas":
        state = "shadow"
    elif ci is None:
        state = "unregistered"
    elif not ci.get("tags_complete", False):
        state = "partial"
    else:
        state = "registered"

    owner = None
    if ci:
        owner = ci.get("owner")
    if not owner:
        tags = resource.get("tags") or {}
        tag_owner = tags.get("Owner")
        if tag_owner:
            owner = f"{tag_owner}@ridgeline-demo.example"
            conf_boost = 0.1
        else:
            conf_boost = 0.0
    else:
        conf_boost = 0.0

    conf = min(0.99, _confidence(resource, ci) + conf_boost)
    if state in ("unregistered", "shadow"):
        owner = owner or "security-ops-queue@ridgeline-demo.example"

    return {
        "asset_id": resource["asset_id"],
        "name": resource.get("name"),
        "platform": resource.get("platform"),
        "env": resource.get("env") or "unknown",
        "type": resource.get("type"),
        "ci_id": None if ci is None else ci.get("ci_id"),
        "registration_state": state,
        "owner": owner,
        "owner_confidence": round(conf, 2),
        "quarantine_class": state in ("unregistered", "shadow", "partial"),
        "sox_in_scope": bool(ci and ci.get("sox_in_scope")),
        "data_class": (ci or {}).get("data_class") or "unknown",
        "mutate_allowed": state == "registered" and conf >= 0.80,
    }


def discover(cmdb: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, Any]]:
    by_ci = {ci["ci_id"]: ci for ci in cmdb.get("cis", [])}
    results = []
    for resource in inventory.get("resources", []):
        ci_id = resource.get("ci_id")
        ci = by_ci.get(ci_id) if ci_id else None
        results.append(classify(resource, ci))
    return results


def inventory_integrity(assets: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(assets) or 1
    counts = {"registered": 0, "partial": 0, "unregistered": 0, "shadow": 0}
    for a in assets:
        counts[a["registration_state"]] = counts.get(a["registration_state"], 0) + 1
    return {
        "discovered": len(assets),
        "counts": counts,
        "registered_ratio": round(counts["registered"] / n, 4),
        "unregistered_count": counts["unregistered"] + counts["shadow"],
    }
