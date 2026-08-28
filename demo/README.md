# Offline proof fixture and architecture guide

This bundle explains the Proof-to-Permit authority boundary and validates a
sanitized evidence bundle without cloud credentials. It keeps scripted
comparison evidence distinct from fresh direct-cloud provider evidence while
checking their shared manifest and cross-file hashes.

## Run it

```bash
uv run --no-sync python scripts/replay_gate_g5r.py
uv run --no-sync python scripts/check_release_candidate.py
```

For machine-readable output:

```bash
uv run --no-sync python scripts/replay_gate_g5r.py --json
```

The first command is an offline evidence-fixture validator. It validates the
[bundle manifest](evidence/proof-to-permit.json),
[provider proof](evidence/provider-proof.json),
[live corroboration](evidence/live-corroboration.json), and
[cleanup verification](evidence/cleanup-verification.json) before printing
anything. It refuses changed counts, hashes, classifications, claim
authorization, permit cardinality, replay behavior, or cleanup inventory. It
does not execute the recovery workflow, invoke Gemini, or contact Google Cloud.

## Evidence layers

| Layer | What it demonstrates | What it does not demonstrate |
| --- | --- | --- |
| Accepted scripted baseline | Under the same provider-shaped drop-after-accept fixture, blind retry creates two revisions and blind abort leaves the chain incomplete. | A live Google Cloud A/B test. |
| [Fresh provider proof](evidence/provider-proof.json) | Source `4d626bb67739ca51c7569124724ea5d7ac8f5c0e`, run `p5r-adaptive-b166ba368d1cbc3e9ab57dee61b3dd74`, and 49 projected events: initial `UNKNOWN`, later correlated revision, deterministic certificates, exact permits, effects `1/1/1`, stable snapshot reread, and replay denial. | Adaptive superiority, measured efficiency, or an active public endpoint. |
| Corroboration and cleanup | Five ready, revision-bound Cloud Run services, three Firestore databases, provider-correlated logs, a durable snapshot reread, then zero retained Phase 5 resources after cleanup. | A currently deployed public service. |

The provider proof is checked in for offline validation and mirrored in the
[public evidence release](https://github.com/OCHOLA-EDDYPHIL/reconcile-proof-to-permit/releases/tag/v0.1.1)
with live corroboration, cleanup verification, and checksums. The scripted
baseline remains a separate evidence layer, not a live-cloud A/B.

Use [proof.svg](proof.svg) for the evidence-layer summary and
[../docs/architecture.svg](../docs/architecture.svg) for the authority and hosted
topology. Both have checked-in Graphviz sources and PNG exports.

## Walkthrough assets

- [script.md](script.md) — reference narration aligned to the fresh provider proof
- [proof.svg](proof.svg) and [proof.png](proof.png) — evidence-layer summary
- [../docs/architecture.svg](../docs/architecture.svg) — authority and hosted topology
- [../docs/architecture.png](../docs/architecture.png) — raster architecture export
- [evidence/proof-to-permit.json](evidence/proof-to-permit.json) — offline bundle
  manifest
- [evidence/provider-proof.json](evidence/provider-proof.json),
  [evidence/live-corroboration.json](evidence/live-corroboration.json), and
  [evidence/cleanup-verification.json](evidence/cleanup-verification.json) —
  hash-linked provider evidence

## Code-path navigation

- Advisory investigation: [recovery_agents.py](../reconcile/recovery_agents.py)
- Evidence admission: [admission.py](../reconcile/evidence/admission.py)
- Deterministic verification:
  [recovery_verification.py](../reconcile/evidence/recovery_verification.py)
- Recovery state machine: [recovery_workflow.py](../reconcile/recovery_workflow.py)
- Permit issue and claim: [permits.py](../reconcile/controller/permits.py) and
  [firestore_permits.py](../reconcile/hosted/firestore_permits.py)
- Guarded provider contact:
  [recovery_dispatch.py](../reconcile/hosted/recovery_dispatch.py)

The offline validation path does not require a live deployment or a public
endpoint.
