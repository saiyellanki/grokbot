"""WORM-style evidence vault with a hash chain. PoC writes once per run directory.

Trail integrity
---------------
Each event stores ``prev_event_hash`` of the prior event (genesis is sha256 of 64 zeros).
``event_hash`` is SHA-256 of the canonical JSON of the event *excluding* ``event_hash``
itself, then prefixed with ``sha256:``. 3LoD re-computes the same digest to detect
truncation or in-place edits. Payload bytes are hashed separately as ``inputs_hash``
after redaction.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redaction import deny_unredacted, redact_payload

DEFAULT_POLICY_VERSION = "ccf-2026.09.1"
DEFAULT_ENV = "prod/synthetic"


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_obj(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


class Vault:
    def __init__(self, root: Path, *, policy_version: str = DEFAULT_POLICY_VERSION, env: str = DEFAULT_ENV):
        self.root = root
        self.evidence_dir = root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.chain: list[dict[str, Any]] = []
        self._prev = "sha256:" + ("0" * 64)
        self.policy_version = policy_version
        self.env = env

    def put(
        self,
        *,
        bot_id: str,
        line: str,
        task_id: str,
        payload: dict[str, Any],
        controls: list[str],
        policy_version: str | None = None,
        collector_id: str | None = None,
        env: str | None = None,
        control_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        safe_payload = redact_payload(copy.deepcopy(payload))
        deny_unredacted(safe_payload)
        inputs_hash = "sha256:" + sha256_obj(safe_payload)
        ids = list(control_ids if control_ids is not None else controls)
        event = {
            "event_id": f"evt-{len(self.chain) + 1:04d}",
            "ts": ts,
            "bot_id": bot_id,
            "collector_id": collector_id or bot_id,
            "line": line,
            "task_id": task_id,
            "inputs_hash": inputs_hash,
            "controls": ids,
            "control_ids": ids,
            "policy_version": policy_version or self.policy_version,
            "env": env or self.env,
            "prev_event_hash": self._prev,
            "synthetic": True,
        }
        event["event_hash"] = "sha256:" + sha256_obj(event)
        record = {"event": event, "payload": safe_payload}
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
            json.dumps(
                {
                    "synthetic": True,
                    "policy_version": self.policy_version,
                    "env": self.env,
                    "trail_integrity": {
                        "algo": "sha256",
                        "event_hash_excludes": ["event_hash"],
                        "genesis_prev": "sha256:" + ("0" * 64),
                        "note": "Recompute event_hash over the event without event_hash; walk prev_event_hash.",
                    },
                    "events": self.chain,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
