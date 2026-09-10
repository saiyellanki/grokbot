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

    print("\nPoC OK — artefacts in", out, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
