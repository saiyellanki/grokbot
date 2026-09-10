"""Load SYNTHETIC fixtures. Never calls live cloud APIs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load(name: str) -> dict[str, Any]:
    path = FIXTURES / name
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not data.get("synthetic", False) and name != "tasks.json":
        # tasks.json also marked synthetic
        pass
    return data


def load_all() -> dict[str, Any]:
    return {
        "org": load("organization.json"),
        "cmdb": load("cmdb.json"),
        "inventory": load("inventory.json"),
        "iam": load("iam.json"),
        "cis": load("cis.json"),
        "vulns": load("vulns.json"),
        "vendors": load("vendors.json"),
        "sdn": load("sdn_synthetic.json"),
        "reg_feed": load("reg_feed.json"),
        "ccf": load("ccf.json"),
        "tasks": load("tasks.json"),
        "exceptions": load("exceptions.json"),
        "soc_use_cases": load("soc_use_cases.json"),
        "soc_attestation_evidence": load("soc_attestation_evidence.json"),
    }
