"""Deterministic bot implementations against SYNTHETIC fixtures. No live APIs."""

from __future__ import annotations

from typing import Any

PRIVILEGE_HOST_JUMP = "privilege_host_jump"


def _asset_map(assets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {a["asset_id"]: a for a in assets}


def privilege_host_jump_attested_count(soc: dict[str, Any] | None) -> int:
    if not soc:
        return 0
    kpis = soc.get("kpis") or {}
    ph = kpis.get("privilege_host_jump") or {}
    if "attested_count" in ph:
        return int(ph["attested_count"])
    return sum(
        1
        for uc in soc.get("use_cases") or []
        if uc.get("asset_class") == PRIVILEGE_HOST_JUMP
        and uc.get("detection_attestation") == "attested"
    )


def si002_has_open_exception(aging: dict[str, Any] | None) -> bool:
    """Current or aging (not breached) CCF-SI-002 exception. Expired tickets do not cover."""
    if not aging:
        return False
    for ticket in aging.get("tickets") or []:
        if ticket.get("control_id") != "CCF-SI-002":
            continue
        if ticket.get("aging_status") in ("current", "aging"):
            return True
    return False


def conclude_si002(
    patch: dict[str, Any],
    soc: dict[str, Any] | None = None,
    aging: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """SI-002 cannot pass while privilege_host_jump detections are unattested.

    A current/aging exception yields inconclusive (not pass). Breached exceptions
    do not cover. Collector kev_open / coverage_gaps remain fail. No live SIEM hits.
    """
    kev_open = int(patch.get("kev_open") or 0)
    patch_gaps = int(patch.get("coverage_gaps") or 0)
    attested = privilege_host_jump_attested_count(soc)
    has_exc = si002_has_open_exception(aging)
    reasons: list[str] = []
    if kev_open:
        reasons.append("kev_open")
    if patch_gaps:
        reasons.append("patch_coverage_gaps")
    if attested == 0:
        reasons.append("privilege_host_jump_unattested")
        reasons.append("soc_use_case_gaps")
    if kev_open or patch_gaps:
        return {"outcome": "fail", "reason": ",".join(reasons), "attested_count": attested}
    if attested == 0:
        if has_exc:
            return {
                "outcome": "inconclusive",
                "reason": "privilege_host_jump_unattested_exception_recorded",
                "attested_count": attested,
            }
        return {
            "outcome": "fail",
            "reason": "privilege_host_jump_unattested,soc_use_case_gaps",
            "attested_count": attested,
        }
    return {"outcome": "pass", "reason": "ok", "attested_count": attested}


def cis_drift_sentinel(cis: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Outer-join discovered inventory to CIS snapshots.

    Assets with snapshots stay in the tested population even when unregistered.
    Discovered assets without a snapshot become explicit coverage_gap rows —
    they are not omitted from the denominator.
    """
    amap = _asset_map(assets)
    findings: list[dict[str, Any]] = []
    snap_asset_ids: set[str] = set()
    for snap in cis.get("snapshots", []):
        asset = amap.get(snap["asset_id"], {})
        snap_asset_ids.add(snap["asset_id"])
        passed = bool(snap["pass"])
        findings.append(
            {
                "rule_id": snap["rule_id"],
                "asset_id": snap["asset_id"],
                "pass": passed,
                "outcome": "pass" if passed else "fail",
                "status": "pass" if passed else "fail",
                "severity": snap.get("severity") or ("info" if passed else "medium"),
                "expected": snap["expected"],
                "observed": snap["observed"],
                "registration_state": asset.get("registration_state", "unregistered"),
                "mutate_allowed": asset.get("mutate_allowed", False),
                "remediation_attempted": False,
            }
        )
    coverage_gap_findings: list[dict[str, Any]] = []
    for asset in assets:
        aid = asset["asset_id"]
        if aid in snap_asset_ids:
            continue
        coverage_gap_findings.append(
            {
                "rule_id": "CIS-COVERAGE",
                "asset_id": aid,
                "pass": False,
                "outcome": "coverage_gap",
                "status": "coverage_gap",
                "severity": "medium",
                "expected": "cis_snapshot_present",
                "observed": "no_cis_snapshot",
                "registration_state": asset.get("registration_state", "unregistered"),
                "mutate_allowed": asset.get("mutate_allowed", False),
                "remediation_attempted": False,
            }
        )
    findings.extend(coverage_gap_findings)
    tested = len(findings) - len(coverage_gap_findings)
    failed = [f for f in findings if f["status"] == "fail"]
    return {
        "bot_id": "cis-drift-sentinel",
        "tested": tested,
        "failed": len(failed),
        "coverage_gaps": len(coverage_gap_findings),
        "population": tested + len(coverage_gap_findings),
        "findings": findings,
        "skipped_unregistered": 0,
        "denominator": "tested + coverage_gaps; unregistered-with-snapshot remain in tested",
        "remediation_attempted": False,
        "notes": (
            "Unregistered assets remain in the test population. "
            "Discovered assets without a CIS snapshot are coverage_gap rows, "
            "not silent omissions. No CIS drift is auto-remediated."
        ),
    }


def iam_entitlement_auditor(iam: dict[str, Any]) -> dict[str, Any]:
    flags = []
    for p in iam.get("principals", []):
        reasons = []
        if p.get("hr_id") is None:
            reasons.append("orphaned")
        if p.get("last_used_days_ago", 0) > 90:
            reasons.append("unused_90d")
        if p.get("standing_admin"):
            reasons.append("standing_admin")
        if p.get("sod_clash"):
            reasons.append("sod_clash")
        if reasons:
            flags.append(
                {
                    "principal_id": p["principal_id"],
                    "platform": p["platform"],
                    "reasons": reasons,
                    "proposed_action": "revocation_diff",
                    "auto_apply": False,
                }
            )
    return {
        "bot_id": "iam-entitlement-auditor",
        "principals_reviewed": len(iam.get("principals", [])),
        "flagged": len(flags),
        "flags": flags,
        "notes": "No deletions. HITL required for SOX-in-scope identity changes.",
    }


def patch_verify_bot(vulns: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    amap = _asset_map(assets)
    rows = []
    for f in vulns.get("findings", []):
        asset = amap.get(f["asset_id"], {})
        coverage_gap = f.get("agent_last_seen_hours") is None and f.get("vendor_attestation") is None
        status = "patched" if f.get("patched") else "unpatched"
        if coverage_gap:
            status = "coverage_gap"
        if f.get("vendor_attestation") and f.get("patched") is None:
            status = "vendor_attested_agentless"
        priority = "P1" if f.get("kev") else "P2"
        if coverage_gap:
            priority = "P2"
        rows.append(
            {
                "finding_id": f["finding_id"],
                "asset_id": f["asset_id"],
                "cve": f.get("cve"),
                "kev": bool(f.get("kev")),
                "status": status,
                "priority": "P1" if f.get("kev") else priority,
                "registration_state": asset.get("registration_state", "unregistered"),
                "hitl_required": bool(f.get("kev")) or not asset.get("mutate_allowed", False),
            }
        )
    return {
        "bot_id": "patch-verify-bot",
        "findings": rows,
        "kev_open": sum(1 for r in rows if r["kev"] and r["status"] != "patched"),
        "coverage_gaps": sum(1 for r in rows if r["status"] == "coverage_gap"),
        "notes": "No agent is a coverage gap, not a pass.",
    }


def ofac_sanctions_screener(vendors: dict[str, Any], sdn: dict[str, Any]) -> dict[str, Any]:
    listed = {e["name"].upper() for e in sdn.get("entries", [])}
    hits = []
    clears = []
    for v in vendors.get("vendors", []):
        name = (v.get("ofac_name") or v["legal_name"]).upper()
        rec = {
            "vendor_id": v["vendor_id"],
            "name": v["name"],
            "legal_name": v["legal_name"],
            "match": name in listed,
            "list": "SYNTHETIC-DEMO" if name in listed else None,
        }
        if rec["match"]:
            hits.append(rec)
        else:
            clears.append(rec)
    return {
        "bot_id": "ofac-sanctions-screener",
        "screened": len(vendors.get("vendors", [])),
        "hits": hits,
        "clears": clears,
        "hitl_required": len(hits) > 0,
        "notes": "Synthetic SDN only. Hits never auto-clear.",
    }


def reg_change_mapper(reg_feed: dict[str, Any], ccf: dict[str, Any]) -> dict[str, Any]:
    """Rule-based mapping drafts. LLM-shaped output without calling a model."""
    keyword_map = {
        "AI": ["CCF-RM-001", "CCF-AM-001"],
        "NPI": ["CCF-AC-001", "CCF-AM-001"],
        "configuration": ["CCF-CM-002"],
        "telemetry": ["CCF-CM-002", "CCF-AU-003"],
        "Unregistered": ["CCF-AM-001"],
        "third-party": ["CCF-SA-001"],
    }
    ccf_ids = {c["ccf_id"] for c in ccf.get("controls", [])}
    drafts = []
    for item in reg_feed.get("items", []):
        blob = " ".join(item.get("obligations", []) + [item.get("title", "")])
        mapped = []
        for kw, ids in keyword_map.items():
            if kw.lower() in blob.lower() or kw in blob:
                mapped.extend(ids)
        mapped = sorted(set(i for i in mapped if i in ccf_ids))
        drafts.append(
            {
                "item_id": item["item_id"],
                "title": item["title"],
                "mapping_draft": mapped or ["CCF-RM-001"],
                "confidence": 0.62 if mapped else 0.40,
                "attestor": None,
                "status": "draft",
            }
        )
    return {
        "bot_id": "reg-change-mapper",
        "drafts": drafts,
        "notes": "mapping_draft only. 2LoD must attest. No CCF write.",
    }


def cct_evidence_harvester(
    ccf: dict[str, Any],
    vault_payloads: dict[str, dict[str, Any]],
    integrity: dict[str, Any],
    soc: dict[str, Any] | None = None,
    aging: dict[str, Any] | None = None,
) -> dict[str, Any]:
    results = []
    soc = soc or vault_payloads.get("soc-use-case-attestor")
    aging = aging or vault_payloads.get("exception-aging")
    for control in ccf.get("controls", []):
        cid = control["ccf_id"]
        bot = control["test_bot"]
        payload = vault_payloads.get(bot)
        reason = None
        if cid == "CCF-AU-003":
            # 3LoD control — 2LoD does not attest independence
            results.append(
                {
                    "ccf_id": cid,
                    "outcome": "not_tested_by_2lod",
                    "reason": "Independence: sampled by 3LoD only",
                }
            )
            continue
        if payload is None:
            results.append({"ccf_id": cid, "outcome": "inconclusive", "reason": "no_evidence"})
            continue
        if cid == "CCF-CM-002":
            failed = payload.get("failed", 0)
            gaps = payload.get("coverage_gaps", 0)
            if failed or gaps:
                outcome = "fail"
                reason = "cis_failed" if failed else "cis_coverage_gaps"
                if failed and gaps:
                    reason = "cis_failed,cis_coverage_gaps"
            else:
                outcome = "pass"
        elif cid in ("CCF-AC-001", "CCF-AC-006"):
            outcome = "fail" if payload.get("flagged", 0) else "pass"
        elif cid == "CCF-SI-002":
            judged = conclude_si002(payload, soc=soc, aging=aging)
            outcome = judged["outcome"]
            reason = judged["reason"]
        elif cid == "CCF-AM-001":
            outcome = "fail" if integrity.get("unregistered_count", 0) else "pass"
        elif cid == "CCF-SA-001":
            outcome = "fail" if payload.get("hits") else "pass"
        elif cid == "CCF-RM-001":
            drafts = payload.get("drafts") or []
            outcome = "inconclusive" if any(d.get("status") == "draft" for d in drafts) else "pass"
        else:
            outcome = "inconclusive"
        rec = {
            "ccf_id": cid,
            "title": control["title"],
            "outcome": outcome,
            "sox_in_scope": control.get("sox_in_scope"),
            "evidence_bot": bot,
            "close_allowed": False,
        }
        if reason:
            rec["reason"] = reason
        results.append(rec)
    return {
        "bot_id": "cct-evidence-harvester",
        "results": results,
        "pass": sum(1 for r in results if r["outcome"] == "pass"),
        "fail": sum(1 for r in results if r["outcome"] == "fail"),
        "inconclusive": sum(1 for r in results if r["outcome"] == "inconclusive"),
        "notes": "Inconclusive is not pass. Close requires 1LoD owner + 2LoD reviewer.",
    }


def independent_sampler(
    vault_payloads: dict[str, dict[str, Any]],
    cct: dict[str, Any],
    chain_ok: bool,
) -> dict[str, Any]:
    """Read-only re-performance. Must not enqueue remediations."""
    sample_ids = ["CCF-CM-002", "CCF-AC-006", "CCF-SI-002", "CCF-AM-001"]
    by_ccf = {r["ccf_id"]: r for r in cct.get("results", [])}
    observations = []
    workpapers = []
    for cid in sample_ids:
        two = by_ccf.get(cid, {})
        recomputed = two.get("outcome", "inconclusive")
        # Re-perform CM from raw cis payload (drift + coverage_gaps)
        if cid == "CCF-CM-002":
            cis = vault_payloads.get("cis-drift-sentinel") or {}
            recomputed = "fail" if cis.get("failed", 0) or cis.get("coverage_gaps", 0) else "pass"
        if cid == "CCF-AC-006":
            iam = vault_payloads.get("iam-entitlement-auditor") or {}
            recomputed = "fail" if iam.get("flagged", 0) else "pass"
        if cid == "CCF-SI-002":
            patch = vault_payloads.get("patch-verify-bot") or {}
            soc = vault_payloads.get("soc-use-case-attestor")
            aging = vault_payloads.get("exception-aging")
            recomputed = conclude_si002(patch, soc=soc, aging=aging)["outcome"]
        if cid == "CCF-AM-001":
            recomputed = two.get("outcome", "inconclusive")
        delta = recomputed != two.get("outcome")
        workpapers.append(
            {
                "ccf_id": cid,
                "2lod_outcome": two.get("outcome"),
                "3lod_reperform": recomputed,
                "delta": delta,
            }
        )
        if delta:
            observations.append(
                {
                    "ccf_id": cid,
                    "type": "conclusion_mismatch",
                    "queue": "audit_observation",
                }
            )
    if not chain_ok:
        observations.append(
            {
                "ccf_id": "CCF-AU-003",
                "type": "evidence-integrity-gap",
                "queue": "audit_observation",
            }
        )
    return {
        "bot_id": "independent-sampler",
        "sample_seed": 20260909,
        "sample": sample_ids,
        "workpapers": workpapers,
        "observations": observations,
        "chain_ok": chain_ok,
        "remediation_attempted": False,
        "notes": "3LoD did not call 1LoD bots to fill gaps.",
    }
