#!/usr/bin/env python3
"""Run the Ridgeline Demo Bank ACBN PoC (SYNTHETIC)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from acbn.orchestrator import run  # noqa: E402
from acbn.redaction import REDACTED, deny_unredacted, redact_payload  # noqa: E402


REQUIRED_ARTEFACTS = (
    "exception_aging.json",
    "soc_use_case_attestation.json",
    "cis_drift.json",
    "hitl_tokens.json",
    "vault/chain.json",
    "kpis.json",
)
REQUIRED_EVENT_FIELDS = (
    "policy_version",
    "collector_id",
    "control_ids",
    "env",
    "line",
    "prev_event_hash",
    "event_hash",
)


def _fail(msg: str) -> int:
    print(f"FAIL: {msg}", file=sys.stderr)
    return 1


def main() -> int:
    out = ROOT / "out"
    summary = run(out)
    print(json.dumps(summary, indent=2))
    if not summary.get("chain_ok"):
        return _fail("vault hash-chain")
    if summary["kpis"]["unauthorized_prod_mutations"] != 0:
        return _fail("unauthorized mutations")
    if not summary.get("token_reuse_rejected"):
        return _fail("dual-control token reuse was not rejected")
    for name in REQUIRED_ARTEFACTS:
        if not (out / name).exists():
            return _fail(f"missing artefact {name}")

    probe = redact_payload({"ssn": "000-00-0000", "pan": "4111111111111111", "ok": True})
    if probe["ssn"] != REDACTED or probe["pan"] != REDACTED or probe["ok"] is not True:
        return _fail("redaction stub did not strip NPI/CHD keys")
    deny_unredacted(probe)

    tokens = json.loads((out / "hitl_tokens.json").read_text(encoding="utf-8"))
    if tokens.get("reuse_across_tasks", {}).get("rejected_reason") != "token_reuse_across_tasks":
        return _fail("expected token_reuse_across_tasks on unbound task")
    if tokens.get("reuse_after_consume", {}).get("ok"):
        return _fail("token replay after consume was accepted")

    chain = json.loads((out / "vault/chain.json").read_text(encoding="utf-8"))
    for event in chain.get("events") or []:
        missing = [f for f in REQUIRED_EVENT_FIELDS if f not in event]
        if missing:
            return _fail(f"{event.get('event_id')} missing {missing}")

    cis = json.loads((out / "cis_drift.json").read_text(encoding="utf-8"))
    if cis.get("skipped_unregistered") != 0:
        return _fail("cis skipped_unregistered must stay 0")
    if cis.get("remediation_attempted"):
        return _fail("cis remediation_attempted must be false")
    unreg_tested = [
        f
        for f in cis.get("findings") or []
        if f.get("registration_state") != "registered" and f.get("status") != "coverage_gap"
    ]
    if not unreg_tested:
        return _fail("unregistered assets with snapshots must remain in the CIS test population")
    gaps = {f["asset_id"]: f for f in cis.get("findings") or [] if f.get("status") == "coverage_gap"}
    shadow = gaps.get("okta:app:quicknote-ai")
    if not shadow or shadow.get("registration_state") != "shadow":
        return _fail("okta:app:quicknote-ai must be coverage_gap with registration_state=shadow")
    for aid in ("salesforce:00DDEMO0000001", "q2:tenant-rhb-demo", "fiserv:dna-rhb-demo"):
        if aid not in gaps:
            return _fail(f"{aid} must appear as CIS coverage_gap")

    soc = json.loads((out / "soc_use_case_attestation.json").read_text(encoding="utf-8"))
    soc_kpis = soc.get("kpis") or {}
    ph = soc_kpis.get("privilege_host_jump") or {}
    attested = int(ph.get("attested_count") or 0)
    ratio = soc_kpis.get("soc_use_case_coverage_ratio")
    if ratio != soc_kpis.get("detection_attested_rate"):
        return _fail("soc_use_case_coverage_ratio must come from the attestation artefact")
    if summary["kpis"].get("soc_use_case_coverage_ratio") != ratio:
        return _fail("kpis.soc_use_case_coverage_ratio must match attestation artefact")

    irm = json.loads((out / "irm.json").read_text(encoding="utf-8"))
    si002 = next((r for r in (irm.get("cct") or {}).get("results") or [] if r.get("ccf_id") == "CCF-SI-002"), None)
    if si002 is None:
        return _fail("CCT missing CCF-SI-002")
    if attested == 0 and si002.get("outcome") == "pass":
        return _fail("CCF-SI-002 cannot pass while privilege_host_jump attested_count==0")
    if attested == 0 and "soc_use_case_gaps" not in (si002.get("reason") or "") and "privilege_host_jump_unattested" not in (
        si002.get("reason") or ""
    ):
        return _fail("CCF-SI-002 reason must point at privilege_host_jump / soc use-case gaps")

    sampler = json.loads((out / "3lod_sample.json").read_text(encoding="utf-8"))
    if sampler.get("remediation_attempted"):
        return _fail("3LoD remediation_attempted must be false")
    si002_3 = next((w for w in sampler.get("workpapers") or [] if w.get("ccf_id") == "CCF-SI-002"), None)
    if si002_3 and si002_3.get("3lod_reperform") == "pass" and attested == 0:
        return _fail("3LoD SI-002 re-perform cannot be pass while privilege_host_jump attested_count==0")

    print("\nPoC OK — artefacts in", out, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
