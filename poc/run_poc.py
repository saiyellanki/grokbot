#!/usr/bin/env python3
"""Run the Ridgeline Demo Bank ACBN PoC (SYNTHETIC)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from acbn.orchestrator import run  # noqa: E402


def main() -> int:
    out = ROOT / "out"
    summary = run(out)
    print(json.dumps(summary, indent=2))
    if not summary.get("chain_ok"):
        print("FAIL: vault hash-chain", file=sys.stderr)
        return 1
    if summary["kpis"]["unauthorized_prod_mutations"] != 0:
        print("FAIL: unauthorized mutations", file=sys.stderr)
        return 1
    print("\nPoC OK — artefacts in", out, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
