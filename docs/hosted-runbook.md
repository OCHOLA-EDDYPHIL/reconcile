# Hosted recovery runbook

This runbook describes the maintainer-operated path for an authorized Google
Cloud environment. The recorded environment was ephemeral and was removed after
evidence capture.

## What is portable and what is sealed

Application contracts, the container, evidence rules, and the operator state
machine are in the repository. Terraform backends, service identities, billing
bindings, and budgets are sealed to a maintainer environment. Do not copy those
identifiers into another project or treat the current infrastructure as a
turnkey template.

An operator targeting another project must parameterize and review every
backend, identity, IAM, billing, region, database, and service assumption. That
is separate infrastructure work.

## Prerequisites

- An exact clean source revision and reviewed `uv.lock`
- Python 3.12.13 and uv 0.12.3
- Terraform 1.15.8 with Google provider 7.44.0
- Docker 29.6.2 and Google Cloud CLI 580.0.0
- A dedicated Google Cloud project and billing account with an approved budget
- Application Default Credentials for an operator allowed to impersonate the
  reviewed apply identity
- Required Google APIs, Cloud Run, Firestore databases, Artifact Registry,
  Storage buckets, and service accounts provisioned from reviewed plans
- Explicit approval bound to the exact manifest, source, image, infrastructure,
  semantic configuration, budget, and work window

Never commit credentials or raw operator state. Use an operator-owned directory
outside the checkout and an external secret store.

## Sealed operator sequence

Discover the interface without mutating cloud state:

```bash
uv run --no-sync python scripts/phase5_operator.py --help
uv run --no-sync python scripts/phase5_operator.py inspect \
  --state-dir <operator-state>
```

The state machine is:

1. `prepare-artifacts` records toolchain, source, dependency, container,
   Terraform, semantic configuration, cost, and action-plan custody.
2. `seal-manifest` refuses a dirty or mismatched source tree.
3. `record-approval` binds an approver and timestamp to the manifest hash.
4. `run` accepts only the sealed manifest and approval for one named action:
   bootstrap, foundation, image, runtime, provider acceptance, hosted
   acceptance, or a corresponding teardown action.
5. `inspect` reads the durable action and evidence chain after every boundary.

There is no “deploy everything” shortcut. Obtain a reviewed plan before every
apply and use the exact manifest and approval hashes printed by the preceding
commands.

## Recovery invocation

With an authorized deployment and identity-aware endpoint:

```bash
export RECONCILE_API_URL="https://<api-service>"
export RECONCILE_API_AUDIENCE="https://<api-audience>"

uv run --no-sync reconcile recovery run cloud-run-rollout \
  --policy adaptive \
  --fault drop-after-accept \
  --run-id <unique-run-id>
```

The command is remote-only. The default loopback API does not provision Cloud
Run or Firestore and must not be presented as a hosted recovery demonstration.

## Acceptance criteria

Accept a recorded run only when one trace establishes all of these outcomes:

1. Initial ambiguity is `UNKNOWN`; continuation and retry are denied; no action
   permit exists.
2. A later pass observes one exact correlated and settled revision.
3. Deterministic verification issues the exact certificate and `max_uses=1`
   permit for each continuation.
4. Exactly one revision, one promotion, and one Firestore release record exist.
5. Reusing consumed authority is rejected before provider contact.
6. Raw evidence is sealed, a sanitized provider evidence record is linked, and
   cleanup leaves zero scoped cloud resources.

These criteria cover the hosted recovery path. They do not establish model
superiority, performance, portability, or a general exactly-once guarantee.

## Provider degradation and safe stop

If Gemini, Cloud Run, Firestore, identity, or an authoritative read is
unavailable, do not widen authority or infer success from a timeout. Preserve
the evidence, emit `UNKNOWN` or an ambiguity witness, deny mutation, and stop.

If teardown automation returns an unknown result, do not blindly replay it.
Read provider state, use an exact reviewed cleanup plan, preserve both records,
and independently inventory the scoped project afterward.

## Evidence references

The recorded outcomes and evidence hashes are in the
[provider evidence record](../demo/evidence/provider-proof.json). Teardown
evidence and the zero-resource inventory are in
[cleanup verification](../demo/evidence/cleanup-verification.json).
