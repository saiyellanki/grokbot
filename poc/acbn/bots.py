"""Deterministic bot implementations against SYNTHETIC fixtures. No live APIs."""

from __future__ import annotations

from typing import Any


def _asset_map(assets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {a["asset_id"]: a for a in assets}


def cis_drift_sentinel(cis: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    amap = _asset_map(assets)
    findings = []
    for snap in cis.get("snapshots", []):
        asset = amap.get(snap["asset_id"], {})
        findings.append(
            {
                "rule_id": snap["rule_id"],
                "asset_id": snap["asset_id"],
                "pass": snap["pass"],
                "severity": snap.get("severity") or ("info" if snap["pass"] else "medium"),
                "expected": snap["expected"],
                "observed": snap["observed"],
                "registration_state": asset.get("registration_state", "unregistered"),
                "mutate_allowed": asset.get("mutate_allowed", False),
            }
        )
    failed = [f for f in findings if not f["pass"]]
    return {
        "bot_id": "cis-drift-sentinel",
        "tested": len(findings),
        "failed": len(failed),
        "findings": findings,
        "skipped_unregistered": 0,
        "notes": "Unregistered assets remain in the test population.",
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
) -> dict[str, Any]:
    results = []
    for control in ccf.get("controls", []):
        cid = control["ccf_id"]
        bot = control["test_bot"]
        payload = vault_payloads.get(bot)
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
            outcome = "fail" if failed else "pass"
        elif cid in ("CCF-AC-001", "CCF-AC-006"):
            outcome = "fail" if payload.get("flagged", 0) else "pass"
        elif cid == "CCF-SI-002":
            outcome = "fail" if payload.get("kev_open", 0) or payload.get("coverage_gaps", 0) else "pass"
        elif cid == "CCF-AM-001":
            outcome = "fail" if integrity.get("unregistered_count", 0) else "pass"
        elif cid == "CCF-SA-001":
            outcome = "fail" if payload.get("hits") else "pass"
        elif cid == "CCF-RM-001":
            drafts = payload.get("drafts") or []
            outcome = "inconclusive" if any(d.get("status") == "draft" for d in drafts) else "pass"
        else:
            outcome = "inconclusive"
        results.append(
            {
                "ccf_id": cid,
                "title": control["title"],
                "outcome": outcome,
                "sox_in_scope": control.get("sox_in_scope"),
                "evidence_bot": bot,
                "close_allowed": False,
            }
        )
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
        # Re-perform CM from raw cis payload
        if cid == "CCF-CM-002":
            cis = vault_payloads.get("cis-drift-sentinel") or {}
            recomputed = "fail" if cis.get("failed", 0) else "pass"
        if cid == "CCF-AC-006":
            iam = vault_payloads.get("iam-entitlement-auditor") or {}
            recomputed = "fail" if iam.get("flagged", 0) else "pass"
        if cid == "CCF-SI-002":
            patch = vault_payloads.get("patch-verify-bot") or {}
            recomputed = "fail" if patch.get("kev_open", 0) or patch.get("coverage_gaps", 0) else "pass"
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
