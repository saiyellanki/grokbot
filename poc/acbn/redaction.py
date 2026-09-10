"""Deny unredacted NPI/CHD in vault payloads. Synthetic-safe key redaction.

Vault writers must not persist raw nonpublic personal information or cardholder
data. This stub strips keys whose names match a deny-pattern and replaces the
value with ``[REDACTED]``. Fixtures in this PoC do not contain real NPI/CHD;
the policy exists so an accidental key cannot land in the hash-chained evidence.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

# Key names only — do not invent live customer records to test these.
SENSITIVE_KEY_RE = re.compile(
    r"("
    r"ssn|social_security|itin|"
    r"pan|primary_account|card_number|cardnumber|credit_card|cvv|cvc|chd|"
    r"npi_raw|npi_value|full_npi|"
    r"account_number|routing_number|iban|"
    r"dob|date_of_birth|"
    r"drivers_license|passport_number"
    r")",
    re.IGNORECASE,
)


def key_is_sensitive(key: str) -> bool:
    return bool(SENSITIVE_KEY_RE.search(str(key)))


def redact_payload(obj: Any) -> Any:
    """Return a copy-safe walk that redacts matching keys in-place on *obj*."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if key_is_sensitive(k):
                out[k] = REDACTED
            else:
                out[k] = redact_payload(v)
        return out
    if isinstance(obj, list):
        return [redact_payload(item) for item in obj]
    return obj


def unredacted_sensitive_keys(obj: Any, *, prefix: str = "") -> list[str]:
    """Paths whose keys match the deny list and whose values are not already redacted."""
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if key_is_sensitive(k) and v != REDACTED:
                found.append(path)
            else:
                found.extend(unredacted_sensitive_keys(v, prefix=path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(unredacted_sensitive_keys(item, prefix=f"{prefix}[{i}]"))
    return found


def deny_unredacted(obj: Any) -> None:
    leftover = unredacted_sensitive_keys(obj)
    if leftover:
        raise ValueError(f"unredacted NPI/CHD keys denied in vault payload: {leftover}")
