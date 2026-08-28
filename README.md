# RECONCILE

> Never let an agent guess whether an action happened.

RECONCILE is a proof layer for ambiguous agent side effects. When a tool call
times out after a consequential action, it investigates the provider state,
classifies only admitted evidence, and issues a narrow single-use permit for the
next exact action—or refuses to mutate.

**Gemini investigates. Deterministic evidence decides.**

[Validate the offline evidence fixture](#validate-the-offline-evidence-fixture) ·
[Inspect the fresh provider proof](demo/evidence/provider-proof.json) ·
[Read the claims and limitations](docs/claims-and-limitations.md) ·
[Use the demo bundle](demo/README.md)

![Scripted policy fixture and separate direct Google Cloud trace](demo/proof.svg)

## The failure mode

An agent asks Cloud Run to stage a revision. Cloud Run accepts the mutation, but
the acknowledgement disappears. The agent now sees a timeout, not the outcome.

| Policy | What happens after the lost acknowledgement |
| --- | --- |
| Blind retry | Repeats the stage mutation and can create a second release-labelled revision. |
| Blind abort | Leaves the accepted revision staged while the old revision keeps serving. |
| Proof-to-Permit | Holds both retry and continuation until provider evidence proves the exact next action. |

The baseline row values come from an accepted scripted, provider-shaped
qualification—not a live-cloud A/B. The direct Google Cloud candidate separately
proved that the recovery path works against Cloud Run and Firestore.

## Validate the offline evidence fixture

Prerequisites: Git, Python 3.12.13, and
[uv 0.12.3](https://docs.astral.sh/uv/). The lockfile is authoritative.

```bash
git clone https://github.com/OCHOLA-EDDYPHIL/reconcile-proof-to-permit.git
cd reconcile-proof-to-permit
uv sync --locked --all-groups
uv run --no-sync python scripts/replay_gate_g5r.py
uv run --no-sync python scripts/check_release_candidate.py
```

The first command is an offline validator for a sanitized, checked-in evidence
fixture. It checks frozen classifications, counts, hashes, permit constraints,
and replay behavior; it does not rerun the recovery workflow, call Gemini, or
contact Google Cloud. The validated outcome is:

```text
Accepted scripted baseline | fault: drop-after-accept
  blind retry  -> 2 revisions, 1 promotion, 1 record (duplicate revision)
  blind abort  -> 1 staged revision, 0 promotions, 0 records (incomplete chain)

Accepted direct live-cloud trace | source 4d626bb
  pass 1       -> UNKNOWN; CONTINUE denied; RETRY denied; 0 recovery-action permits
  pass 2       -> COMMITTED; 1 exact correlated revision
  authority    -> deterministic certificates; two max_uses=1 permits
  evidence     -> 49 durable events; provider/live projection hash linked
  effects      -> 1 revision / 1 promotion / 1 Firestore record
  replay       -> rejected before provider contact; contact delta 0
  cleanup      -> zero retained Phase 5 cloud resources

RESULT: PASS
```

This is offline evidence-fixture validation, not recovery execution or a
substitute for a provider run. The validator checks the manifest and its linked,
checked-in provider proof, corroboration, and cleanup record; the same evidence
is published with hashes. The ephemeral deployment was deliberately cleaned up,
and the validator does not depend on a public endpoint.

## How it works

1. [`RolloutAgent`](reconcile/recovery_agents.py) binds an intended release chain:
   stage, promote, and record.
2. A durable dispatch gate records provider contact and the lost acknowledgement.
3. [`RecoveryAgent`](reconcile/recovery_agents.py) invokes an ADK-backed Gemini
   3.5 Flash planner for an evidence-cited hypothesis and bounded read-only probe
   proposals.
4. [Evidence admission](reconcile/evidence/admission.py) applies capability,
   freshness, provenance, and correlation rules to provider observations.
5. [Deterministic verification](reconcile/evidence/recovery_verification.py)
   produces either a verified certificate or an ambiguity witness. Model text is
   never an authorization input.
6. The [recovery workflow](reconcile/recovery_workflow.py) may issue an expiring
   permit for one exact semantic action with `max_uses=1`; the
   [Firestore permit store](reconcile/hosted/firestore_permits.py) durably
   arbitrates its claim.
7. The [dispatcher](reconcile/hosted/recovery_dispatch.py) consumes that permit
   before provider contact. Replay is denied before a second call can leave the
   process.

![Proof-to-Permit authority and trust boundaries](docs/architecture.svg)

The diagram source is [docs/architecture.dot](docs/architecture.dot).

## What the Google stack does

| Technology | Critical-path role |
| --- | --- |
| Gemini 3.5 Flash on Vertex AI | Generates a bound hypothesis and proposes useful evidence reads under a budget. |
| Google ADK | Provides the `LlmAgent` and `Runner` boundary for the stateless advisory Gemini planner turn. |
| Cloud Run | Hosts API, controller, fault proxy, sandbox, and canary services; the canary is the real stage-and-promotion target. |
| Firestore | Separates runtime authority state, isolated sandbox state, and target release records across three databases. |
| Cloud Storage | Holds sealed operator and infrastructure artifacts for hosted execution. |
| Google IAM | Gives each service its own identity: the controller can investigate and verify, while the fault proxy alone receives the bounded target-mutation role. |

Gemini improves the investigation surface; it does not decide whether the effect
occurred. That separation is the product's central trust boundary.

## Evidence

The [public evidence release](https://github.com/OCHOLA-EDDYPHIL/reconcile-proof-to-permit/releases/tag/v0.1.1)
keeps the fresh provider record, corroboration, cleanup record, and checksums
together. Its live-cloud lineage remains distinct from the scripted qualification:

| Evidence layer | Lineage | Purpose |
| --- | --- | --- |
| [Fresh provider proof](demo/evidence/provider-proof.json) | source `4d626bb67739ca51c7569124724ea5d7ac8f5c0e`; run `p5r-adaptive-b166ba368d1cbc3e9ab57dee61b3dd74`; 49 projected events | Records initial `UNKNOWN`, later exact revision correlation, deterministic certificates, two exact permits, effects `1/1/1`, stable snapshot reread, and zero-contact replay rejection. |
| [Live corroboration](demo/evidence/live-corroboration.json) | same public release | Records five ready, revision-bound Cloud Run services, three Firestore databases, provider-correlated logs, and the durable 49-event snapshot reread. |
| [Cleanup verification](demo/evidence/cleanup-verification.json) | same public release | Records the post-capture cleanup state. |
| [Offline bundle manifest](demo/evidence/proof-to-permit.json) | scripted qualification plus hash-linked provider, corroboration, and cleanup artifacts | Lets the local validator check the full checked-in bundle without cloud credentials; it does not rerun the provider workflow. |

The offline qualification represented by the fixture covers 100 scripted cases,
400 policy lanes, and zero false recovery-action permits.

The frozen matrix authorized the wording **“proof-to-permit safety on the frozen
recovery matrix.”** It did not authorize adaptive-efficiency or model-superiority
wording: the observed 20% median probe reduction missed the preregistered 25%
threshold.

## Interfaces

```bash
uv run --no-sync reconcile --help
uv run --no-sync reconcile recovery run --help
uv run --no-sync reconcile-api
```

The recovery command targets a configured hosted API; it is not a local Cloud Run
emulator. Maintainer-operated deployment, identity, approval, reset, evidence,
and cleanup requirements are in the [hosted runbook](docs/hosted-runbook.md).

## Repository map

- [`reconcile/recovery_agents.py`](reconcile/recovery_agents.py) — RolloutAgent,
  RecoveryAgent, and dispatch boundary
- [`reconcile/recovery_workflow.py`](reconcile/recovery_workflow.py) — durable
  Proof-to-Permit lifecycle
- [`reconcile/evidence/`](reconcile/evidence/) — evidence admission,
  deterministic rules, and verification
- [`reconcile/controller/permits.py`](reconcile/controller/permits.py) — exact
  permit issue, claim, completion, and denial
- [`reconcile/hosted/`](reconcile/hosted/) — Google Cloud adapters and durable
  hosted stores
- [`schemas/`](schemas/) — versioned public contracts
- [`demo/`](demo/) — offline fixture, visual summary, and reference narration

## Claim boundary

RECONCILE currently proves a deliberately narrow recovery chain: an ambiguous
Cloud Run revision stage, an exact traffic promotion, and one Firestore release
record. It complements idempotency keys, provider operation handles, workflow
engines, sagas, and transactional outboxes; it does not replace them.

Security, privacy, portability, cost, provider-degradation behavior, prior art,
and all non-claims are explicit in
[docs/claims-and-limitations.md](docs/claims-and-limitations.md).
