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

Designed defects (on purpose): incomplete CMDB, unregistered personal S3, shadow SaaS (QuickNote AI), orphan IAM user, SoD clash, synthetic KEV on a jump host, synthetic SDN name match, agentless Q2/Fiserv.

## Run

```bash
python3 poc/run_poc.py
```

Writes `poc/out/`:

- `vault/evidence/` + `vault/chain.json` — hash-chained artefacts
- `assets.json` — discovery states (`registered | partial | unregistered | shadow`)
- `irm.json` / `hitl_queue.json` — issues; mutations blocked
- `3lod_sample.json` / `examiner_pack.md`
- `kpis.json` — **computed** from this run, labeled SYNTHETIC

## Grok / agent path

Follow [playbooks/grok-e2e.md](playbooks/grok-e2e.md). The Python bots are the deterministic control plane; Grok plays HITL (1LoD/2LoD/CISO) and 3LoD narrative, and must not invent live-cloud remediations.

## Guardrails

- Phase 2 only: evidence + HITL queue. Autonomy grants list is empty.
- 3LoD cannot call the action broker (enforced: `remediation_attempted` must stay false).
- OFAC list is `sdn_synthetic.json`, not Treasury SDN.
- Dummy NPI/CHD is not present in fixtures; do not add real customer data.
