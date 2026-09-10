# ACBN PoC — Ridgeline Demo Bank (SYNTHETIC)

End-to-end proof of the [Autonomous Cybersecurity Bot Network](../docs/autonomous-cybersecurity-bot-network.md) against a **fictitious** US regional bank. No live AWS, Azure, core-banking, or OFAC SDN calls.

## Tenant

| Field | Value |
| --- | --- |
| Legal name | Ridgeline Demo Bank, N.A. |
| Org ID | `lhb-poc-0001` |
| Charter | `OCC-SYN-99999` (fictitious) |
| HQ | Austin, TX |
| CISO | Dana Okonkwo |
| 1LoD | Jordan Hale (Cloud & IAM) |
| 2LoD | Priya Nair (Cyber Risk) |
| 3LoD | Morgan Ellis (IT Audit) |

Designed defects (on purpose): incomplete CMDB, unregistered personal S3, shadow SaaS (QuickNote AI), orphan IAM user, SoD clash, synthetic KEV on a jump host, synthetic SDN name match, agentless Q2/Fiserv, expired risk-accept tickets, SOC detection gaps on the privilege-host path.

## Run

```bash
python3 poc/run_poc.py
```

Writes `poc/out/`:

- `vault/evidence/` + `vault/chain.json` — hash-chained artefacts
- `assets.json` — discovery states (`registered | partial | unregistered | shadow`)
- `irm.json` / `hitl_queue.json` — issues; mutations blocked
- `exception_aging.json` — risk-accept / exception tickets classified current / aging / breached
- `soc_use_case_attestation.json` — privilege-host KEV use-cases; collectors ≠ detection
- `hitl_tokens.json` — dual-control token demo (reuse across tasks rejected)
- `3lod_sample.json` / `examiner_pack.md`
- `kpis.json` — **computed** from this run, labeled SYNTHETIC

Pass when stderr prints `PoC OK` and `run_summary.json` has `chain_ok: true` and `kpis.unauthorized_prod_mutations: 0`.

## Vault event schema

Each chain event includes:

| Field | Notes |
| --- | --- |
| `policy_version` | CCF bundle id, e.g. `ccf-2026.09.1` |
| `collector_id` | Defaults to `bot_id` |
| `controls` / `control_ids` | Same list (alias) |
| `env` | Default `prod/synthetic` |
| `line` | `1LOD` / `2LOD` / `3LOD` |
| `prev_event_hash` / `event_hash` | `event_hash` is SHA-256 of the event **excluding itself** |

`chain.json` records the trail-integrity note. 3LoD walks `prev_event_hash` and recomputes each digest.

Payloads are redacted before `inputs_hash`. Keys matching NPI/CHD patterns (`ssn`, `pan`, `cvv`, `account_number`, …) are replaced with `[REDACTED]`. Unredacted leftovers are denied. Fixtures do not contain real customer data.

## Exception aging

Fixture: `poc/fixtures/exceptions.json`. As-of `2026-09-10T00:00:00Z`:

- `breached` — `as_of > expires_at` → HITL `escalate_expired_exception`
- `aging` — within 14 days of expiry → HITL `review_aging_exception`
- `current` — otherwise, no HITL

Aged/breached tickets are appended to `hitl_queue.json`. No ticket is auto-closed.

## SOC use-case library

Fixture: `poc/fixtures/soc_use_cases.json` (privilege-host KEV / jump-host):

| ID | Phase | MITRE (illustrative) |
| --- | --- | --- |
| UC-PH-001 | exploit | T1190, T1210 |
| UC-PH-002 | post-exploit shell | T1059, T1021.001 |
| UC-PH-003 | lateral-to-NPI | T1021, T1530 |
| UC-PH-004 | KEV aging | T1190 |

`collector_coverage` and `detection_attested_rate` are separate KPIs. A `kev_open` collector finding is not an attested detection use-case.

## Dual-control tokens

Schema: `approver_id`, `sod_peer_id`, `expires_at`, `bound_task_id`, `action`, `asset_or_principal`.

The in-memory broker consumes a token once and rejects reuse on a different `task_id`. Phase 2 records the decision only — no production mutation.

## Grok / agent path

Follow [playbooks/grok-e2e.md](playbooks/grok-e2e.md). The Python bots are the deterministic control plane; Grok plays HITL (1LoD/2LoD/CISO) and 3LoD narrative, and must not invent live-cloud remediations.

## Guardrails

- Phase 2 only: evidence + HITL queue. Autonomy grants list is empty.
- 3LoD cannot call the action broker (enforced: `remediation_attempted` must stay false).
- OFAC list is `sdn_synthetic.json`, not Treasury SDN.
- Dummy NPI/CHD is not present in fixtures; do not add real customer data.
- No live AWS, Azure, OFAC, Q2, or Fiserv calls.
