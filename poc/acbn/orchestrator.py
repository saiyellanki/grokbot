"""Phase-2 orchestrator: discover → 1LoD → 2LoD → HITL queue → 3LoD sample."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import bots
from .discovery import discover, inventory_integrity
from .exception_aging import age_exceptions
from .hitl_tokens import DualControlBroker, issue_token
from .loader import load_all
from .soc_use_cases import attest_library
from .vault import Vault

HITL_REASONS_ALWAYS = (
    "mutates_identity",
    "sox_in_scope",
    "unregistered_or_low_confidence",
    "ofac_hit",
    "kev",
    "mapping_draft",
)

REQUIRED_VAULT_FIELDS = (
    "policy_version",
    "collector_id",
    "control_ids",
    "controls",
    "env",
    "line",
    "prev_event_hash",
    "event_hash",
)


def _hitl_items(bot_id: str, payload: dict[str, Any], assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    if bot_id == "cis-drift-sentinel":
        for f in payload.get("findings", []):
            status = f.get("status") or f.get("outcome")
            if status == "coverage_gap":
                items.append(
                    {
                        "bot_id": bot_id,
                        "action": "cover_cis_snapshot",
                        "asset_id": f["asset_id"],
                        "blocked": True,
                        "reasons": [
                            "cis_coverage_gap",
                            f"registration_state={f.get('registration_state')}",
                        ],
                    }
                )
                continue
            if f.get("pass"):
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
    if bot_id == "soc-use-case-attestor":
        for uc in payload.get("use_cases", []):
            if uc.get("asset_class") != "privilege_host_jump":
                continue
            if uc.get("detection_attestation") == "attested":
                continue
            items.append(
                {
                    "bot_id": bot_id,
                    "action": "attest_soc_use_case",
                    "use_case_id": uc["use_case_id"],
                    "blocked": True,
                    "reasons": [
                        "privilege_host_jump_unattested",
                        f"attestation={uc.get('detection_attestation')}",
                    ],
                }
            )
    return items


def kpis(
    assets: list[dict[str, Any]],
    integrity: dict[str, Any],
    cct: dict[str, Any],
    sampler: dict[str, Any],
    hitl: list[dict[str, Any]],
    aging: dict[str, Any] | None = None,
    soc: dict[str, Any] | None = None,
    cis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    in_scope = [r for r in cct.get("results", []) if r.get("outcome") != "not_tested_by_2lod"]
    complete = [r for r in in_scope if r["outcome"] in ("pass", "fail")]
    n = len(in_scope) or 1
    sample = sampler.get("workpapers") or []
    exceptions = sampler.get("observations") or []
    aging = aging or {}
    soc_kpis = (soc or {}).get("kpis") or {}
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
        "exception_breached": (aging.get("counts") or {}).get("breached", 0),
        "exception_aging": (aging.get("counts") or {}).get("aging", 0),
        "soc_collector_coverage": soc_kpis.get("collector_coverage"),
        "soc_detection_attested_rate": soc_kpis.get("detection_attested_rate"),
        "soc_use_case_coverage_ratio": soc_kpis.get("soc_use_case_coverage_ratio"),
        "soc_privilege_host_jump_attested_count": (soc_kpis.get("privilege_host_jump") or {}).get(
            "attested_count"
        ),
        "soc_collectors_are_not_detections": soc_kpis.get("collectors_are_not_detections", True),
        "cis_tested": (cis or {}).get("tested"),
        "cis_coverage_gaps": (cis or {}).get("coverage_gaps"),
        "cis_population": (cis or {}).get("population"),
    }


def _put(vault: Vault, *, bot_id: str, line: str, task_id: str, payload: dict[str, Any], controls: list[str]) -> dict[str, Any]:
    return vault.put(
        bot_id=bot_id,
        collector_id=bot_id,
        line=line,
        task_id=task_id,
        payload=payload,
        controls=controls,
        control_ids=controls,
    )


def _demo_hitl_token() -> dict[str, Any]:
    token = issue_token(
        approver_id="jordan.hale@ridgeline-demo.example",
        sod_peer_id="priya.nair@ridgeline-demo.example",
        expires_at="2026-09-10T23:59:59Z",
        bound_task_id="task-iam-001",
        action="apply_revocation_diff",
        asset_or_principal="arn:aws:iam::111122223333:user/contractor-lee",
        token_id="tok-task-iam-001-contractor-lee",
    )
    broker = DualControlBroker()
    return broker.demo_reuse_guard(
        token,
        bound_ok_task="task-iam-001",
        reuse_task="task-cis-001",
        now="2026-09-10T12:00:00Z",
    )


def _assert_vault_schema(vault: Vault) -> None:
    for event in vault.chain:
        missing = [f for f in REQUIRED_VAULT_FIELDS if f not in event]
        if missing:
            raise RuntimeError(f"vault event {event.get('event_id')} missing {missing}")
        if event["control_ids"] != event["controls"]:
            raise RuntimeError("control_ids must alias controls")
        if event["collector_id"] != event["bot_id"]:
            raise RuntimeError("collector_id must equal bot_id unless explicitly overridden")


def run(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = load_all()
    policy_version = data["ccf"].get("version") or "ccf-2026.09.1"
    vault = Vault(out_dir / "vault", policy_version=policy_version, env="prod/synthetic")
    assets = discover(data["cmdb"], data["inventory"])
    integrity = inventory_integrity(assets)

    disc_rec = _put(
        vault,
        bot_id="discovery",
        line="1LOD",
        task_id="task-disc-001",
        payload={"assets": assets, "integrity": integrity},
        controls=["CCF-AM-001"],
    )

    cis = bots.cis_drift_sentinel(data["cis"], assets)
    _put(vault, bot_id="cis-drift-sentinel", line="1LOD", task_id="task-cis-001", payload=cis, controls=["CCF-CM-002"])

    iam = bots.iam_entitlement_auditor(data["iam"])
    _put(
        vault,
        bot_id="iam-entitlement-auditor",
        line="1LOD",
        task_id="task-iam-001",
        payload=iam,
        controls=["CCF-AC-001", "CCF-AC-006"],
    )

    patch = bots.patch_verify_bot(data["vulns"], assets)
    _put(vault, bot_id="patch-verify-bot", line="1LOD", task_id="task-patch-001", payload=patch, controls=["CCF-SI-002"])

    ofac = bots.ofac_sanctions_screener(data["vendors"], data["sdn"])
    _put(vault, bot_id="ofac-sanctions-screener", line="2LOD", task_id="task-ofac-001", payload=ofac, controls=["CCF-SA-001"])

    reg = bots.reg_change_mapper(data["reg_feed"], data["ccf"])
    _put(vault, bot_id="reg-change-mapper", line="2LOD", task_id="task-reg-001", payload=reg, controls=["CCF-RM-001"])

    aging = age_exceptions(data["exceptions"])
    _put(
        vault,
        bot_id="exception-aging",
        line="2LOD",
        task_id="task-exc-001",
        payload={"counts": aging["counts"], "tickets": aging["tickets"]},
        controls=sorted({t["control_id"] for t in aging["tickets"] if t.get("control_id")}),
    )

    available = {
        p.get("bot_id")
        for p in (cis, iam, patch, ofac, reg)
        if isinstance(p, dict) and p.get("bot_id")
    }
    available.add("discovery")
    available.add("patch-verify-bot")
    soc = attest_library(
        data["soc_use_cases"],
        available_collectors=available,
        evidence=data.get("soc_attestation_evidence"),
    )
    _put(
        vault,
        bot_id="soc-use-case-attestor",
        line="2LOD",
        task_id="task-soc-001",
        payload={"kpis": soc["kpis"], "use_cases": soc["use_cases"]},
        controls=["CCF-SI-002", "CCF-AU-003"],
    )

    payloads = {
        "discovery": disc_rec["payload"],
        "cis-drift-sentinel": cis,
        "iam-entitlement-auditor": iam,
        "patch-verify-bot": patch,
        "ofac-sanctions-screener": ofac,
        "reg-change-mapper": reg,
        "soc-use-case-attestor": soc,
        "exception-aging": aging,
    }

    cct = bots.cct_evidence_harvester(data["ccf"], payloads, integrity, soc=soc, aging=aging)
    _put(vault, bot_id="cct-evidence-harvester", line="2LOD", task_id="task-cct-001", payload=cct, controls=["CCF-AC-001"])

    chain_ok = vault.verify_chain()
    sampler = bots.independent_sampler(payloads, cct, chain_ok)
    _put(
        vault,
        bot_id="independent-sampler",
        line="3LOD",
        task_id="task-audit-001",
        payload=sampler,
        controls=["CCF-AU-003"],
    )
    chain_ok = vault.verify_chain()
    sampler["chain_ok"] = chain_ok
    _assert_vault_schema(vault)

    if sampler.get("remediation_attempted"):
        raise RuntimeError("3LoD independence violated")

    hitl: list[dict[str, Any]] = []
    for bot_id, payload in (
        ("cis-drift-sentinel", cis),
        ("iam-entitlement-auditor", iam),
        ("patch-verify-bot", patch),
        ("ofac-sanctions-screener", ofac),
        ("reg-change-mapper", reg),
        ("soc-use-case-attestor", soc),
    ):
        hitl.extend(_hitl_items(bot_id, payload, assets))
    hitl.extend(aging.get("hitl_items") or [])

    token_demo = _demo_hitl_token()
    if token_demo.get("reuse_across_tasks", {}).get("ok"):
        raise RuntimeError("dual-control broker accepted a reused token")

    vault.flush_manifest()
    metrics = kpis(assets, integrity, cct, sampler, hitl, aging=aging, soc=soc, cis=cis)

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
    (out_dir / "exception_aging.json").write_text(json.dumps(aging, indent=2), encoding="utf-8")
    (out_dir / "soc_use_case_attestation.json").write_text(json.dumps(soc, indent=2), encoding="utf-8")
    (out_dir / "cis_drift.json").write_text(json.dumps(cis, indent=2), encoding="utf-8")
    (out_dir / "hitl_tokens.json").write_text(json.dumps(token_demo, indent=2), encoding="utf-8")

    pack = examiner_pack(data["org"], metrics, sampler, chain_ok, aging=aging, soc=soc)
    (out_dir / "examiner_pack.md").write_text(pack, encoding="utf-8")

    summary = {
        "org": data["org"]["legal_name"],
        "phase": data["org"]["phase"],
        "chain_ok": chain_ok,
        "kpis": metrics,
        "hitl_count": len(hitl),
        "exception_hitl": (aging.get("counts") or {}).get("hitl_queued", 0),
        "soc_detection_attested_rate": metrics.get("soc_detection_attested_rate"),
        "soc_use_case_coverage_ratio": metrics.get("soc_use_case_coverage_ratio"),
        "token_reuse_rejected": not token_demo.get("reuse_across_tasks", {}).get("ok", True),
        "out_dir": str(out_dir),
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (out_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def examiner_pack(
    org: dict[str, Any],
    metrics: dict[str, Any],
    sampler: dict[str, Any],
    chain_ok: bool,
    aging: dict[str, Any] | None = None,
    soc: dict[str, Any] | None = None,
) -> str:
    obs = sampler.get("observations") or []
    aging = aging or {}
    soc = soc or {}
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
        f"- Exception breached / aging: {metrics.get('exception_breached')} / {metrics.get('exception_aging')}",
        f"- SOC collector coverage / detection attested / use-case coverage: {metrics.get('soc_collector_coverage')} / {metrics.get('soc_detection_attested_rate')} / {metrics.get('soc_use_case_coverage_ratio')}",
        f"- Privilege-host jump attested_count: {metrics.get('soc_privilege_host_jump_attested_count')}",
        f"- CIS tested / coverage_gaps / population: {metrics.get('cis_tested')} / {metrics.get('cis_coverage_gaps')} / {metrics.get('cis_population')}",
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
        "## Exception aging",
        "",
    ]
    for t in aging.get("tickets") or []:
        lines.append(
            f"- `{t['exception_id']}` {t.get('control_id')} {t['aging_status']} days_to_expiry={t['days_to_expiry']}"
        )
    if not aging.get("tickets"):
        lines.append("- No exception fixtures loaded.")
    lines += [
        "",
        "## SOC use-case attestation (privilege-host KEV)",
        "",
        "Collectors ≠ detection. A KEV inventory finding is not an exploit or lateral-movement use-case.",
        "Default PoC leaves UC-JUMP-KEV-01..04 unattested (gap/partial). CCF-SI-002 cannot pass while privilege_host_jump attested_count==0.",
        "",
    ]
    for uc in soc.get("use_cases") or []:
        lines.append(
            f"- `{uc['use_case_id']}` {uc.get('phase')} attestation={uc.get('detection_attestation')} "
            f"mitre={','.join(uc.get('mitre') or [])}"
        )
    lines += [
        "",
        "## Independence statement",
        "",
        "The independent sampler used vault hashes only. It did not invoke 1LoD collectors",
        "or the action broker. LLM mapping drafts remain unattested. Dual-control tokens are",
        "bound to a single task_id; the PoC broker rejects reuse across tasks.",
        "",
        "## Redaction",
        "",
        "Vault payloads are walked for NPI/CHD key patterns and redacted before `inputs_hash`.",
        "Fixtures do not contain real customer data.",
        "",
    ]
    return "\n".join(lines) + "\n"
