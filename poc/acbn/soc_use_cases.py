"""SOC use-case library attestation. Collectors ≠ detection.

Privilege-host / jump-host KEV coverage is scored from a signed-style library
fixture. A collector that inventories a KEV does not attest that the SOC would
see exploit, post-exploit shell, or lateral movement toward NPI.

Synthetic evidence fixtures may upgrade attestation. They are not live SIEM hits.
"""

from __future__ import annotations

from typing import Any

ATTESTED = "attested"
PARTIAL = "partial"
GAP = "gap"
PRIVILEGE_HOST_JUMP = "privilege_host_jump"


def _attestation(uc: dict[str, Any]) -> str:
    det = uc.get("detection") or {}
    status = det.get("attestation") or uc.get("attestation") or GAP
    if status not in (ATTESTED, PARTIAL, GAP):
        return GAP
    return status


def _uc_ids(uc: dict[str, Any]) -> set[str]:
    ids = {uc["use_case_id"]}
    for alias in uc.get("alias_ids") or []:
        ids.add(alias)
    return ids


def _evidence_index(evidence: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Map use_case_id → applied synthetic evidence. apply=false is ignored."""
    index: dict[str, dict[str, Any]] = {}
    if not evidence:
        return index
    for ev in evidence.get("evidence") or []:
        if not ev.get("apply"):
            continue
        ucid = ev.get("use_case_id")
        if not ucid:
            continue
        index[ucid] = ev
    return index


def _match_evidence(uc: dict[str, Any], index: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    for ucid in _uc_ids(uc):
        if ucid in index:
            return index[ucid]
    return None


def attest_library(
    library: dict[str, Any],
    *,
    available_collectors: set[str] | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    collectors = available_collectors or set()
    applied = _evidence_index(evidence)
    rows: list[dict[str, Any]] = []
    for uc in library.get("use_cases", []):
        status = _attestation(uc)
        ev = _match_evidence(uc, applied)
        evidence_applied = False
        evidence_id = None
        if ev:
            ev_status = ev.get("attestation") or ATTESTED
            if ev_status in (ATTESTED, PARTIAL, GAP):
                status = ev_status
                evidence_applied = True
                evidence_id = ev.get("evidence_id")
        listed = list(uc.get("collector_ids") or [])
        present = [c for c in listed if not collectors or c in collectors]
        det = uc.get("detection") or {}
        rows.append(
            {
                "use_case_id": uc["use_case_id"],
                "alias_ids": list(uc.get("alias_ids") or []),
                "title": uc.get("title"),
                "phase": uc.get("phase"),
                "asset_class": uc.get("asset_class") or PRIVILEGE_HOST_JUMP,
                "example_asset_id": uc.get("example_asset_id"),
                "mitre": list(uc.get("mitre") or []),
                "controls": list(uc.get("controls") or []),
                "collector_ids": listed,
                "collectors_present": present,
                "has_collector": bool(listed),
                "has_detection": status == ATTESTED,
                "detection_attestation": status,
                "detection_rule_id": (ev.get("rule_id") if ev and ev.get("rule_id") else None)
                or det.get("rule_id"),
                "synthetic_evidence_applied": evidence_applied,
                "evidence_id": evidence_id,
                "notes": (ev.get("notes") if ev else None) or det.get("notes") or uc.get("notes"),
            }
        )

    n = len(rows) or 1
    attested_n = sum(1 for r in rows if r["detection_attestation"] == ATTESTED)
    partial_n = sum(1 for r in rows if r["detection_attestation"] == PARTIAL)
    gap_n = sum(1 for r in rows if r["detection_attestation"] == GAP)
    collector_n = sum(1 for r in rows if r["has_collector"])
    ph = [r for r in rows if r.get("asset_class") == PRIVILEGE_HOST_JUMP]
    ph_n = len(ph)
    ph_attested = sum(1 for r in ph if r["detection_attestation"] == ATTESTED)
    coverage_ratio = round(attested_n / n, 4)
    ph_coverage = round(ph_attested / (ph_n or 1), 4) if ph_n else 0.0
    return {
        "synthetic": True,
        "disclaimer": (
            "Computed from the privilege-host SOC library fixture plus optional "
            "synthetic evidence. Not a live SIEM attestation. apply=false evidence "
            "is documentation only and does not invent detection hits."
        ),
        "library_id": library.get("library_id"),
        "thesis": library.get("thesis")
        or "Collectors prove exposure. Detection use-cases prove the SOC would see the attack path.",
        "use_cases": rows,
        "kpis": {
            "use_cases": len(rows),
            "collector_coverage": round(collector_n / n, 4),
            "detection_attested_rate": coverage_ratio,
            "soc_use_case_coverage_ratio": coverage_ratio,
            "detection_partial_rate": round(partial_n / n, 4),
            "detection_gap_rate": round(gap_n / n, 4),
            "collectors_are_not_detections": True,
            "privilege_host_jump": {
                "use_cases": ph_n,
                "attested_count": ph_attested,
                "coverage_ratio": ph_coverage,
            },
        },
        "formula": {
            "collector_coverage": "use_cases_with_collector_ids / use_cases",
            "detection_attested_rate": "attestation==attested / use_cases",
            "soc_use_case_coverage_ratio": "attestation==attested / use_cases (same artefact)",
            "privilege_host_jump.coverage_ratio": (
                "privilege_host_jump attestation==attested / privilege_host_jump use_cases"
            ),
            "note": "A collector finding (e.g. kev_open) is not a detection use-case attestation.",
        },
        "gap_path": (
            "Default PoC leaves UC-JUMP-KEV-01..04 unattested (gap/partial). "
            "Set apply=true on a synthetic evidence row to demo an attested UC."
        ),
    }
