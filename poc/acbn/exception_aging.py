"""Age risk-accept / exception tickets. Expired items escalate to HITL.

All tickets are SYNTHETIC. This module does not close exceptions or invent
production remediations — it classifies aging and queues human review.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

AGING_WINDOW_DAYS = 14
DEFAULT_AS_OF = "2026-09-10T00:00:00Z"


def _parse_ts(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_of(doc: dict[str, Any], override: str | None) -> datetime:
    raw = override or doc.get("as_of") or DEFAULT_AS_OF
    return _parse_ts(raw)


def classify_ticket(ticket: dict[str, Any], as_of: datetime) -> dict[str, Any]:
    expires = _parse_ts(ticket["expires_at"])
    delta = expires - as_of
    days_to_expiry = int(delta.total_seconds() // 86400)
    if as_of > expires:
        aging_status = "breached"
        escalate = True
        reason = "exception_expired"
        action = "escalate_expired_exception"
    elif days_to_expiry <= AGING_WINDOW_DAYS:
        aging_status = "aging"
        escalate = True
        reason = "exception_aging"
        action = "review_aging_exception"
    else:
        aging_status = "current"
        escalate = False
        reason = None
        action = None
    rec = {
        **ticket,
        "aging_status": aging_status,
        "days_to_expiry": days_to_expiry,
        "escalate": escalate,
        "synthetic": True,
    }
    hitl = None
    if escalate:
        hitl = {
            "bot_id": "exception-aging",
            "action": action,
            "exception_id": ticket["exception_id"],
            "control_id": ticket.get("control_id"),
            "owner": ticket.get("owner"),
            "blocked": True,
            "reasons": [reason, f"status={ticket.get('status')}"],
        }
    return {"ticket": rec, "hitl": hitl}


def age_exceptions(doc: dict[str, Any], *, as_of: str | None = None) -> dict[str, Any]:
    when = _as_of(doc, as_of)
    tickets: list[dict[str, Any]] = []
    hitl_items: list[dict[str, Any]] = []
    for raw in doc.get("exceptions", []):
        classified = classify_ticket(raw, when)
        tickets.append(classified["ticket"])
        if classified["hitl"]:
            hitl_items.append(classified["hitl"])
    breached = sum(1 for t in tickets if t["aging_status"] == "breached")
    aging = sum(1 for t in tickets if t["aging_status"] == "aging")
    current = sum(1 for t in tickets if t["aging_status"] == "current")
    return {
        "synthetic": True,
        "disclaimer": "Computed from Ridgeline Demo Bank exception fixtures. Not production tickets.",
        "as_of": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "aging_window_days": AGING_WINDOW_DAYS,
        "formula": {
            "breached": "as_of > expires_at",
            "aging": f"0 <= days_to_expiry <= {AGING_WINDOW_DAYS}",
            "current": f"days_to_expiry > {AGING_WINDOW_DAYS}",
        },
        "counts": {
            "total": len(tickets),
            "breached": breached,
            "aging": aging,
            "current": current,
            "hitl_queued": len(hitl_items),
        },
        "tickets": tickets,
        "hitl_items": hitl_items,
    }
