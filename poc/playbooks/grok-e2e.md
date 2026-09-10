# Grok E2E playbook — Ridgeline Demo Bank (SYNTHETIC)

You are operating the ACBN PoC. All entities are fictitious. Do not call live cloud, core, or OFAC APIs.

## Objective

Prove the bot mesh end-to-end: discovery → 1LoD telemetry bots → 2LoD CCT/OFAC/reg-change → exception aging → SOC use-case attestation → HITL queue → dual-control token guard → 3LoD independent sample.

## Steps

1. Read `poc/README.md` and `docs/autonomous-cybersecurity-bot-network.md` (trust boundaries).
2. Run `python3 poc/run_poc.py`. If it fails, fix code; do not hand-wave evidence.
3. Open `poc/out/kpis.json` and `poc/out/examiner_pack.md`. Quote **computed** figures only.
4. Confirm vault events in `poc/out/vault/chain.json` carry `policy_version`, `collector_id`, `control_ids`, `env`, and `line`. Recompute one `event_hash` excluding itself if you challenge integrity.
5. As **1LoD (Jordan Hale)**: review `hitl_queue.json`. For each item, decide approve / defer / reject with a one-line control rationale. You may not apply IAM or network changes in this phase. Dual-control tokens (`hitl_tokens.json`) are bound to one `task_id`; do not reuse them.
6. As **2LoD (Priya Nair)**: attest or reject `reg-change-mapper` drafts. Inconclusive ≠ pass. Do not close CCT fails without 1LoD owner. Review `exception_aging.json` — expired risk-accepts escalate; do not silently extend them. Review `soc_use_case_attestation.json` — collectors ≠ detection.
7. As **3LoD (Morgan Ellis)**: use `3lod_sample.json` only. If you need more evidence, write an observation — do not re-run 1LoD bots to fill the pack.
8. As **CISO (Dana Okonkwo)**: confirm `unauthorized_prod_mutations == 0` and that Phase 4 grants remain empty.

## Pass criteria

- Vault `chain_ok` is true; `event_hash` excludes itself; `prev_event_hash` walks
- Unregistered / shadow assets appear in CIS and inventory tests; snapshot-less assets are `coverage_gap` (including shadow `okta:app:quicknote-ai`)
- `CCF-SI-002` is not `pass` while privilege_host_jump `attested_count==0`
- OFAC synthetic hit is HITL-blocked
- Aged / breached exceptions appear on the HITL queue
- SOC library scores collector coverage separately from detection attestation
- Dual-control token reuse across tasks is rejected (`token_reuse_rejected: true`)
- 3LoD `remediation_attempted` is false
- `unauthorized_prod_mutations == 0`
- No real customer data and no real SDN list
- No live AWS / Azure / OFAC / Q2 / Fiserv calls

## Output

A short 3LoD memo: what the bots found, which exceptions aged out, which privilege-host detections remain gaps, what HITL still owns, what would be required before any autonomy grant.
