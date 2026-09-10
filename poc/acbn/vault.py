"""WORM-style evidence vault with a hash chain. PoC writes once per run directory."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_obj(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


class Vault:
    def __init__(self, root: Path):
        self.root = root
        self.evidence_dir = root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.chain: list[dict[str, Any]] = []
        self._prev = "sha256:" + ("0" * 64)

    def put(
        self,
        *,
        bot_id: str,
        line: str,
        task_id: str,
        payload: dict[str, Any],
        controls: list[str],
    ) -> dict[str, Any]:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        inputs_hash = "sha256:" + sha256_obj(payload)
        event = {
            "event_id": f"evt-{len(self.chain) + 1:04d}",
            "ts": ts,
            "bot_id": bot_id,
            "line": line,
            "task_id": task_id,
            "inputs_hash": inputs_hash,
            "controls": controls,
            "prev_event_hash": self._prev,
            "synthetic": True,
        }
        event["event_hash"] = "sha256:" + sha256_obj(event)
        record = {"event": event, "payload": payload}
        path = self.evidence_dir / f"{event['event_id']}-{bot_id}.json"
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        self.chain.append(event)
        self._prev = event["event_hash"]
        return record

    def verify_chain(self) -> bool:
        prev = "sha256:" + ("0" * 64)
        for event in self.chain:
            if event["prev_event_hash"] != prev:
                return False
            check = {k: v for k, v in event.items() if k != "event_hash"}
            if "sha256:" + sha256_obj(check) != event["event_hash"]:
                return False
            prev = event["event_hash"]
        return True

    def flush_manifest(self) -> None:
        (self.root / "chain.json").write_text(
            json.dumps({"synthetic": True, "events": self.chain}, indent=2),
            encoding="utf-8",
        )
