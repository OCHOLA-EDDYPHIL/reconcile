# Claims, prior art, and limitations

This document defines the supported public claim surface. Other documentation
must not broaden it.

## Supported claims

| Claim | Basis |
| --- | --- |
| `proof-to-permit safety on the frozen recovery matrix.` | Scripted qualification: 100 cases, 400 lanes, zero false permits, and fixed/adaptive decision and permit parity in all 100 cases. This wording is a frozen compatibility claim. |
| Blind retry duplicated the stage effect in the drop-after-accept fixture. | Two release-labelled revisions, one promotion, and one record. |
| Blind abort left the chain incomplete in that fixture. | One staged revision, zero promotions, and zero records; the baseline revision kept serving. |
| The recorded provider run failed closed before settlement. | The initial pass was `UNKNOWN`; continuation and retry were denied; no recovery-action permit was issued. |
| The settled provider pass continued the exact chain. | One correlated revision, hash-bound deterministic certificates, two `max_uses=1` permits, one promotion, and one Firestore record. |
| Permit replay stopped before provider contact. | Replay outcome `REJECTED_BEFORE_PROVIDER_CONTACT`, contact delta zero. |

The scripted matrix compares policies under one declared fault. The provider
evidence record demonstrates the recovery path against Google Cloud. The
provider run did not execute live blind-retry, blind-abort, or fixed comparison
lanes.

## Withheld claims

- No claim that Gemini or adaptive planning outperforms the fixed planner. The
  scripted adaptive lane used 325 probes versus 370 fixed, with medians of 2 and
  2.5. The 20% median reduction missed the preregistered 25% threshold.
- No claim that model use reduced latency, tokens, or cost. Scripted model calls
  did not measure provider token or billing data.
- No general exactly-once guarantee. The observed result is one exact bounded
  chain under durable identities, evidence rules, preconditions, and permit CAS.
- No claim that arbitrary MCP tools or every provider can be reconciled. A target
  needs stable semantic identity and authoritative read-after-write evidence.
- No claim that the checked-in JSON is the original transcript. It is a sanitized
  derivative whose values and immutable hashes come from the recorded gate data.
- No active hosted-service claim. The recorded environment was ephemeral and was
  removed after evidence capture.

## Why this is not “just retry”

Retries answer *when should the caller try again?* RECONCILE first answers *what
did the provider already do?* An exact retry or continuation is available only
after deterministic evidence rules establish that action as safe.

## Relationship to prior art

- **Idempotency keys** are the first choice when a provider offers a durable key
  with well-defined replay semantics. RECONCILE helps when that contract is
  absent, partial, or does not cover a multi-step release chain.
- **Provider operation IDs and status APIs** are high-value evidence sources.
  They become verifier inputs, not substitutes for effect-specific checks.
- **Workflow engines, retries, and sagas** coordinate durable progress and
  compensation. RECONCILE supplies an evidence-bound decision at an ambiguous
  step before that workflow retries, continues, compensates, or holds.
- **Transactional outboxes, inboxes, and leases** protect boundaries an
  application controls. They cannot by themselves establish what an external
  provider accepted after an acknowledgement was lost.
- **Logs, traces, and observability** explain attempts. RECONCILE admits only
  facts that satisfy source, correlation, freshness, and effect rules before
  mutation.

## Trust and safety boundary

Gemini output is advisory and untrusted. It can propose a hypothesis and
allowlisted read-only probes. It cannot create a certificate, issue a permit,
alter permit scope, or cause provider contact. Stale, conflicting, insufficient,
or unavailable evidence produces an ambiguity witness and a hold.

The public evidence bundle contains no credentials, access tokens, project
secrets, or private evidence locations. Hosted operators must keep raw provider
artifacts and identity material outside the repository.

## Current limitations

- **Target:** the recorded path is Cloud Run stage → traffic promotion →
  Firestore release record. New actions require explicit effects, probes, and
  verifier rules.
- **Provider:** recovery quality is bounded by authoritative, correlated provider
  reads. Unavailable or eventually inconsistent evidence can prolong `UNKNOWN`.
- **Portability:** hosted infrastructure is sealed to a maintainer-operated
  Google Cloud environment; it is not a turnkey deploy-to-any-project template.
- **Operations:** approval, budget controls, IAM preflight, evidence custody,
  cleanup, and provider degradation remain human responsibilities.
- **Cost:** Cloud Run, Firestore, Storage, Artifact Registry, logging, and Vertex
  AI can incur charges. The recorded environment was removed after capture.
- **Privacy:** provider responses and model prompts may include operational
  metadata. Production use needs retention, redaction, residency, and access
  rules.
- **Model availability:** provider failure never widens authority. The workflow
  fails closed or uses an explicitly configured deterministic route.
- **Published evidence:** the public record contains evidence hashes and a
  sanitized summary, not private raw provider data or an event transcript.
- **Viewer:** the viewer serves a static projection of one versioned evidence
  bundle. Its source revision and the evidence source revision are separate,
  and it cannot invoke the operational core or authorize an action.

## Evidence index

- [Provider evidence record](../evidence/v0.1.0/provider-proof.json)
- [Hash-linked live corroboration](../evidence/v0.1.0/live-corroboration.json)
- [Cleanup verification](../evidence/v0.1.0/cleanup-verification.json)
- [Scripted qualification manifest](../evidence/v0.1.0/proof-to-permit.json)
- [v0.1.0 evidence release](https://github.com/OCHOLA-EDDYPHIL/reconcile/releases/tag/v0.1.0)
