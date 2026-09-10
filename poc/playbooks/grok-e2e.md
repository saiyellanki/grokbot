# Grok E2E playbook — Ridgeline Demo Bank (SYNTHETIC)

You are operating the ACBN PoC. All entities are fictitious. Do not call live cloud, core, or OFAC APIs.

## Objective

Prove the bot mesh end-to-end: discovery → 1LoD telemetry bots → 2LoD CCT/OFAC/reg-change → HITL queue → 3LoD independent sample.

## Steps

1. Read `poc/README.md` and `docs/autonomous-cybersecurity-bot-network.md` (trust boundaries).
2. Run `python3 poc/run_poc.py`. If it fails, fix code; do not hand-wave evidence.
3. Open `poc/out/kpis.json` and `poc/out/examiner_pack.md`. Quote **computed** figures only.
4. As **1LoD (Jordan Hale)**: review `hitl_queue.json`. For each item, decide approve / defer / reject with a one-line control rationale. You may not apply IAM or network changes in this phase.
5. As **2LoD (Priya Nair)**: attest or reject `reg-change-mapper` drafts. Inconclusive ≠ pass. Do not close CCT fails without 1LoD owner.
6. As **3LoD (Morgan Ellis)**: use `3lod_sample.json` only. If you need more evidence, write an observation — do not re-run 1LoD bots to fill the pack.
7. As **CISO (Dana Okonkwo)**: confirm `unauthorized_prod_mutations == 0` and that Phase 4 grants remain empty.

## Pass criteria

- Vault `chain_ok` is true
- Unregistered / shadow assets appear in CIS and inventory tests
- OFAC synthetic hit is HITL-blocked
- 3LoD `remediation_attempted` is false
- No real customer data and no real SDN list

## Output

A short 3LoD memo: what the bots found, what HITL still owns, what would be required before any autonomy grant.
