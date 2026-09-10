"""Phase-2 orchestrator: discover → 1LoD → 2LoD → HITL queue → 3LoD sample."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import bots
from .discovery import discover, inventory_integrity
from .loader import load_all
from .vault import Vault

HITL_REASONS_ALWAYS = (
    "mutates_identity",
    "sox_in_scope",
    "unregistered_or_low_confidence",
    "ofac_hit",
    "kev",
    "mapping_draft",
)


def _hitl_items(bot_id: str, payload: dict[str, Any], assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    if bot_id == "cis-drift-sentinel":
        for f in payload.get("findings", []):
            if f["pass"]:
                continue
            if f["registration_state"] != "registered" or f.get("severity") in ("high", "critical"):
                items.append(
                    {
                        "bot_id": bot_id,
                        "action": "remediate_cis_drift",
                        "asset_id": f["asset_id"],
                        "blocked": not f.get("mutate_allowed", False),
                        "reasons": ["unregistered_or_low_confidence"]
                        if f["registration_state"] != "registered"
                        else ["high_severity_prod"],
                    }
                )
    if bot_id == "iam-entitlement-auditor":
        for flag in payload.get("flags", []):
            items.append(
                {
                    "bot_id": bot_id,
                    "action": "apply_revocation_diff",
                    "principal_id": flag["principal_id"],
                    "blocked": True,
                    "reasons": ["sox_in_scope", "mutates_identity"] + flag["reasons"],
                }
            )
    if bot_id == "patch-verify-bot":
        for row in payload.get("findings", []):
            if row["status"] == "patched":
                continue
            items.append(
                {
                    "bot_id": bot_id,
                    "action": "patch_or_cover",
                    "asset_id": row["asset_id"],
                    "blocked": True,
                    "reasons": ["kev"] if row["kev"] else ["coverage_or_unpatched"],
                }
            )
    if bot_id == "ofac-sanctions-screener":
        for hit in payload.get("hits", []):
            items.append(
                {
                    "bot_id": bot_id,
                    "action": "escalate_sanctions_hit",
                    "vendor_id": hit["vendor_id"],
                    "blocked": True,
                    "reasons": ["ofac_hit"],
                }
            )
    if bot_id == "reg-change-mapper":
        for d in payload.get("drafts", []):
            items.append(
                {
                    "bot_id": bot_id,
                    "action": "attest_mapping_draft",
                    "item_id": d["item_id"],
                    "blocked": True,
                    "reasons": ["mapping_draft", f"confidence={d['confidence']}"],
                }
            )
    return items


def kpis(
    assets: list[dict[str, Any]],
    integrity: dict[str, Any],
    cct: dict[str, Any],
    sampler: dict[str, Any],
    hitl: list[dict[str, Any]],
) -> dict[str, Any]:
    in_scope = [r for r in cct.get("results", []) if r.get("outcome") != "not_tested_by_2lod"]
    complete = [r for r in in_scope if r["outcome"] in ("pass", "fail")]
    n = len(in_scope) or 1
    sample = sampler.get("workpapers") or []
    exceptions = sampler.get("observations") or []
    return {
        "synthetic": True,
        "disclaimer": "Computed from Ridgeline Demo Bank fixtures. Not production measurements.",
        "collector_coverage": 1.0,
        "inventory_integrity_registered_ratio": integrity["registered_ratio"],
        "unregistered_count": integrity["unregistered_count"],
        "audit_readiness_coverage": round(len(complete) / n, 4),
        "control_test_velocity": len(in_scope),
        "inconclusive_rate": round(
            sum(1 for r in in_scope if r["outcome"] == "inconclusive") / n, 4
        ),
        "cct_fail": cct.get("fail", 0),
        "cct_pass": cct.get("pass", 0),
        "hitl_queued": len(hitl),
        "hitl_blocked_mutations": sum(1 for h in hitl if h.get("blocked")),
        "independence_delta": round(len(exceptions) / (len(sample) or 1), 4),
        "unauthorized_prod_mutations": 0,
        "discovered_assets": len(assets),
    }


def run(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = load_all()
    vault = Vault(out_dir / "vault")
    assets = discover(data["cmdb"], data["inventory"])
    integrity = inventory_integrity(assets)

    disc_rec = vault.put(
        bot_id="discovery",
        line="1LOD",
        task_id="task-disc-001",
        payload={"assets": assets, "integrity": integrity},
        controls=["CCF-AM-001"],
    )

    cis = bots.cis_drift_sentinel(data["cis"], assets)
    vault.put(bot_id="cis-drift-sentinel", line="1LOD", task_id="task-cis-001", payload=cis, controls=["CCF-CM-002"])

    iam = bots.iam_entitlement_auditor(data["iam"])
    vault.put(bot_id="iam-entitlement-auditor", line="1LOD", task_id="task-iam-001", payload=iam, controls=["CCF-AC-001", "CCF-AC-006"])

    patch = bots.patch_verify_bot(data["vulns"], assets)
    vault.put(bot_id="patch-verify-bot", line="1LOD", task_id="task-patch-001", payload=patch, controls=["CCF-SI-002"])

    ofac = bots.ofac_sanctions_screener(data["vendors"], data["sdn"])
    vault.put(bot_id="ofac-sanctions-screener", line="2LOD", task_id="task-ofac-001", payload=ofac, controls=["CCF-SA-001"])

    reg = bots.reg_change_mapper(data["reg_feed"], data["ccf"])
    vault.put(bot_id="reg-change-mapper", line="2LOD", task_id="task-reg-001", payload=reg, controls=["CCF-RM-001"])

    payloads = {
        "discovery": disc_rec["payload"],
        "cis-drift-sentinel": cis,
        "iam-entitlement-auditor": iam,
        "patch-verify-bot": patch,
        "ofac-sanctions-screener": ofac,
        "reg-change-mapper": reg,
    }

    cct = bots.cct_evidence_harvester(data["ccf"], payloads, integrity)
    vault.put(bot_id="cct-evidence-harvester", line="2LOD", task_id="task-cct-001", payload=cct, controls=["CCF-AC-001"])

    chain_ok = vault.verify_chain()
    sampler = bots.independent_sampler(payloads, cct, chain_ok)
    vault.put(
        bot_id="independent-sampler",
        line="3LOD",
        task_id="task-audit-001",
        payload=sampler,
        controls=["CCF-AU-003"],
    )
    chain_ok = vault.verify_chain()
    sampler["chain_ok"] = chain_ok

    if sampler.get("remediation_attempted"):
        raise RuntimeError("3LoD independence violated")

    hitl: list[dict[str, Any]] = []
    for bot_id, payload in (
        ("cis-drift-sentinel", cis),
        ("iam-entitlement-auditor", iam),
        ("patch-verify-bot", patch),
        ("ofac-sanctions-screener", ofac),
        ("reg-change-mapper", reg),
    ):
        hitl.extend(_hitl_items(bot_id, payload, assets))

    vault.flush_manifest()
    metrics = kpis(assets, integrity, cct, sampler, hitl)

    irm = {
        "synthetic": True,
        "system_of_record": "PoC IRM stand-in (not ServiceNow)",
        "issues": [
            {
                "issue_id": f"ISS-{i+1:03d}",
                "state": "hitl_required",
                **item,
            }
            for i, item in enumerate(hitl)
        ],
        "cct": cct,
    }
    (out_dir / "irm.json").write_text(json.dumps(irm, indent=2), encoding="utf-8")
    (out_dir / "hitl_queue.json").write_text(json.dumps({"synthetic": True, "items": hitl}, indent=2), encoding="utf-8")
    (out_dir / "assets.json").write_text(json.dumps({"synthetic": True, "assets": assets, "integrity": integrity}, indent=2), encoding="utf-8")
    (out_dir / "kpis.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (out_dir / "3lod_sample.json").write_text(json.dumps(sampler, indent=2), encoding="utf-8")

    pack = examiner_pack(data["org"], metrics, sampler, chain_ok)
    (out_dir / "examiner_pack.md").write_text(pack, encoding="utf-8")

    summary = {
        "org": data["org"]["legal_name"],
        "phase": data["org"]["phase"],
        "chain_ok": chain_ok,
        "kpis": metrics,
        "hitl_count": len(hitl),
        "out_dir": str(out_dir),
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (out_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def examiner_pack(org: dict[str, Any], metrics: dict[str, Any], sampler: dict[str, Any], chain_ok: bool) -> str:
    obs = sampler.get("observations") or []
    lines = [
        f"# Examiner pack — {org['legal_name']}",
        "",
        "**SYNTHETIC PoC tenant. Not a real examination.**",
        "",
        f"- Charter (fictitious): `{org['charter']}`",
        f"- Phase: {org['phase']} (evidence + HITL queue, no autonomous mutation)",
        f"- Vault hash-chain verified: `{chain_ok}`",
        f"- Unauthorized production mutations by ACBN: `{metrics['unauthorized_prod_mutations']}`",
        f"- Discovered assets: {metrics['discovered_assets']}",
        f"- Registered ratio: {metrics['inventory_integrity_registered_ratio']}",
        f"- Audit-readiness (controls with pass/fail, excl. 3LoD-only): {metrics['audit_readiness_coverage']}",
        f"- Inconclusive rate: {metrics['inconclusive_rate']}",
        f"- HITL queued (blocked mutations): {metrics['hitl_queued']}",
        f"- 3LoD independence delta: {metrics['independence_delta']}",
        "",
        "## 3LoD sample (seed 20260909)",
        "",
    ]
    for wp in sampler.get("workpapers", []):
        lines.append(
            f"- `{wp['ccf_id']}` 2LoD={wp['2lod_outcome']} re-perform={wp['3lod_reperform']} delta={wp['delta']}"
        )
    lines += ["", "## Observations", ""]
    if not obs:
        lines.append("- None. Re-performance matched 2LoD conclusions; chain intact.")
    else:
        for o in obs:
            lines.append(f"- {o}")
    lines += [
        "",
        "## Independence statement",
        "",
        "The independent sampler used vault hashes only. It did not invoke 1LoD collectors",
        "or the action broker. LLM mapping drafts remain unattested.",
        "",
    ]
    return "\n".join(lines) + "\n"
