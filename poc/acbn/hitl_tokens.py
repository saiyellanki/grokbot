"""Dual-control HITL approval tokens. Broker rejects reuse across tasks.

Schema (framework §1.4): approver_id, sod_peer_id, expires_at, bound_task_id,
plus PoC fields action and asset_or_principal.

Phase 2: tokens are recorded only. The broker never mutates production.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

TOKEN_FIELDS = (
    "approver_id",
    "sod_peer_id",
    "expires_at",
    "bound_task_id",
    "action",
    "asset_or_principal",
)


class TokenError(ValueError):
    """Broker rejection (reuse, binding, expiry, or SoD)."""


def _parse_ts(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def issue_token(
    *,
    approver_id: str,
    sod_peer_id: str,
    expires_at: str,
    bound_task_id: str,
    action: str,
    asset_or_principal: str,
    token_id: str | None = None,
) -> dict[str, Any]:
    if not approver_id or not sod_peer_id:
        raise TokenError("approver_id and sod_peer_id are required")
    if approver_id == sod_peer_id:
        raise TokenError("sod_peer_id must differ from approver_id")
    tid = token_id or f"tok-{bound_task_id}"
    return {
        "token_id": tid,
        "approver_id": approver_id,
        "sod_peer_id": sod_peer_id,
        "expires_at": expires_at,
        "bound_task_id": bound_task_id,
        "action": action,
        "asset_or_principal": asset_or_principal,
        "synthetic": True,
    }


class DualControlBroker:
    """In-memory PoC broker. One consume per token_id; bound_task_id must match."""

    def __init__(self) -> None:
        self._consumed: dict[str, str] = {}

    def consume(
        self,
        token: dict[str, Any],
        *,
        task_id: str,
        now: str | None = None,
    ) -> dict[str, Any]:
        missing = [f for f in TOKEN_FIELDS if not token.get(f)]
        if missing:
            raise TokenError(f"token missing fields: {missing}")
        token_id = token.get("token_id") or f"tok-{token['bound_task_id']}"
        if token_id in self._consumed:
            raise TokenError("token_already_consumed")
        if token["bound_task_id"] != task_id:
            raise TokenError("token_reuse_across_tasks")
        if token["approver_id"] == token["sod_peer_id"]:
            raise TokenError("sod_peer_id must differ from approver_id")
        as_of = _parse_ts(now) if now else datetime.now(timezone.utc)
        if as_of > _parse_ts(token["expires_at"]):
            raise TokenError("token_expired")
        self._consumed[token_id] = task_id
        return {
            "ok": True,
            "token_id": token_id,
            "task_id": task_id,
            "mutated": False,
            "note": "Phase 2: consume recorded; no production mutation.",
        }

    def demo_reuse_guard(
        self,
        token: dict[str, Any],
        *,
        bound_ok_task: str,
        reuse_task: str,
        now: str,
    ) -> dict[str, Any]:
        """Issue-path helper: first consume succeeds; cross-task reuse is rejected."""
        first: dict[str, Any]
        reuse: dict[str, Any]
        try:
            first = self.consume(token, task_id=bound_ok_task, now=now)
        except TokenError as exc:
            first = {"ok": False, "task_id": bound_ok_task, "rejected_reason": str(exc)}
        try:
            self.consume(token, task_id=reuse_task, now=now)
            reuse = {"ok": True, "task_id": reuse_task, "rejected_reason": None}
        except TokenError as exc:
            reuse = {"ok": False, "task_id": reuse_task, "rejected_reason": str(exc)}
        return {
            "synthetic": True,
            "schema": list(TOKEN_FIELDS),
            "broker_rule": "Reject tokens reused across tasks; one consume per token_id.",
            "issued": token,
            "consume_bound_task": first,
            "reuse_across_tasks": reuse,
            "notes": "Phase 2: tokens are recorded only. Broker does not mutate prod.",
        }
