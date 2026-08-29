# Offline evidence bundle and diagrams

This bundle keeps the scripted policy comparison separate from the recorded
Google Cloud evidence while validating their shared manifest and cross-file
hashes. It needs no cloud credentials.

## Run it

```bash
uv run --no-sync python scripts/validate_evidence.py
uv run --no-sync python scripts/check_release_candidate.py
```

For machine-readable output:

```bash
uv run --no-sync python scripts/validate_evidence.py --json
```

The validator checks the [evidence bundle manifest](evidence/proof-to-permit.json),
[provider evidence record](evidence/provider-proof.json),
[live corroboration](evidence/live-corroboration.json), and
[cleanup verification](evidence/cleanup-verification.json). It rejects changed
counts, hashes, classifications, claim authorization, permit cardinality,
replay behavior, or cleanup inventory. It does not execute recovery, invoke
Gemini, or contact Google Cloud.

## Evidence layers

| Layer | What it demonstrates | What it does not demonstrate |
| --- | --- | --- |
| Scripted baseline | Under one provider-shaped drop-after-accept fixture, blind retry creates two revisions and blind abort leaves the chain incomplete. | A live Google Cloud policy comparison. |
| [Provider evidence record](evidence/provider-proof.json) | Initial `UNKNOWN`, later exact revision correlation, deterministic certificates, exact permits, effects `1/1/1`, stable snapshot reread, and replay denial across 49 projected events. | Adaptive superiority, measured efficiency, or an active public endpoint. |
| Corroboration and cleanup | Revision-bound Cloud Run services, isolated Firestore databases, correlated logs, a durable snapshot reread, and zero retained resources after cleanup. | A currently deployed public service. |

The checked-in files are also published in the
[v0.1.0 evidence release](https://github.com/OCHOLA-EDDYPHIL/reconcile/releases/tag/v0.1.0)
with checksums. The scripted baseline remains a separate evidence layer.

## Diagram assets

- [proof.png](proof.png) and [proof.dot](proof.dot) — evidence-layer summary
- [../docs/architecture.png](../docs/architecture.png) and
  [../docs/architecture.dot](../docs/architecture.dot) — recovery authority and
  trust boundaries
- [../docs/deployment.png](../docs/deployment.png) and
  [../docs/deployment.dot](../docs/deployment.dot) — hosted services and identity
  boundaries
- [script.md](script.md) — reference narration

## Evidence files

- [evidence/proof-to-permit.json](evidence/proof-to-permit.json) — compatibility
  manifest for the offline evidence bundle
- [evidence/provider-proof.json](evidence/provider-proof.json) — provider evidence
  record
- [evidence/live-corroboration.json](evidence/live-corroboration.json) —
  hash-linked provider corroboration
- [evidence/cleanup-verification.json](evidence/cleanup-verification.json) —
  hash-linked cleanup inventory

## Code paths

- Advisory investigation: [recovery_agents.py](../reconcile/recovery_agents.py)
- Evidence admission: [admission.py](../reconcile/evidence/admission.py)
- Deterministic verification:
  [recovery_verification.py](../reconcile/evidence/recovery_verification.py)
- Recovery state machine: [recovery_workflow.py](../reconcile/recovery_workflow.py)
- Permit issue and claim: [permits.py](../reconcile/controller/permits.py) and
  [firestore_permits.py](../reconcile/hosted/firestore_permits.py)
- Guarded provider contact:
  [recovery_dispatch.py](../reconcile/hosted/recovery_dispatch.py)

Offline evidence validation does not require a live deployment or public
endpoint.
