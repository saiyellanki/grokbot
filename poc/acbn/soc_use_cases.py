"""SOC use-case library attestation. Collectors ≠ detection.

Privilege-host / jump-host KEV coverage is scored from a signed-style library
fixture. A collector that inventories a KEV does not attest that the SOC would
see exploit, post-exploit shell, or lateral movement toward NPI.
"""

from __future__ import annotations

from typing import Any

ATTESTED = "attested"
PARTIAL = "partial"
GAP = "gap"


def _attestation(uc: dict[str, Any]) -> str:
    det = uc.get("detection") or {}
    status = det.get("attestation") or uc.get("attestation") or GAP
    if status not in (ATTESTED, PARTIAL, GAP):
        return GAP
    return status


def attest_library(
    library: dict[str, Any],
    *,
    available_collectors: set[str] | None = None,
) -> dict[str, Any]:
    collectors = available_collectors or set()
    rows: list[dict[str, Any]] = []
    for uc in library.get("use_cases", []):
        status = _attestation(uc)
        listed = list(uc.get("collector_ids") or [])
        present = [c for c in listed if not collectors or c in collectors]
        rows.append(
            {
                "use_case_id": uc["use_case_id"],
                "title": uc.get("title"),
                "phase": uc.get("phase"),
                "asset_class": uc.get("asset_class"),
                "example_asset_id": uc.get("example_asset_id"),
                "mitre": list(uc.get("mitre") or []),
                "controls": list(uc.get("controls") or []),
                "collector_ids": listed,
                "collectors_present": present,
                "has_collector": bool(listed),
                "has_detection": status == ATTESTED,
                "detection_attestation": status,
                "detection_rule_id": (uc.get("detection") or {}).get("rule_id"),
                "notes": (uc.get("detection") or {}).get("notes") or uc.get("notes"),
            }
        )

    n = len(rows) or 1
    attested_n = sum(1 for r in rows if r["detection_attestation"] == ATTESTED)
    partial_n = sum(1 for r in rows if r["detection_attestation"] == PARTIAL)
    gap_n = sum(1 for r in rows if r["detection_attestation"] == GAP)
    collector_n = sum(1 for r in rows if r["has_collector"])
    return {
        "synthetic": True,
        "disclaimer": "Computed from the privilege-host SOC library fixture. Not a live SIEM attestation.",
        "library_id": library.get("library_id"),
        "thesis": library.get("thesis")
        or "Collectors prove exposure. Detection use-cases prove the SOC would see the attack path.",
        "use_cases": rows,
        "kpis": {
            "use_cases": len(rows),
            "collector_coverage": round(collector_n / n, 4),
            "detection_attested_rate": round(attested_n / n, 4),
            "detection_partial_rate": round(partial_n / n, 4),
            "detection_gap_rate": round(gap_n / n, 4),
            "collectors_are_not_detections": True,
        },
        "formula": {
            "collector_coverage": "use_cases_with_collector_ids / use_cases",
            "detection_attested_rate": "attestation==attested / use_cases",
            "note": "A collector finding (e.g. kev_open) is not a detection use-case attestation.",
        },
    }
