# Claims, prior art, and limitations

This is the frozen claim surface for the release candidate. A demo, README, or
submission draft must not broaden it.

## Supported claims

| Claim | Basis |
| --- | --- |
| Proof-to-Permit was safe on the frozen recovery matrix. | Accepted scripted qualification: 100 cases, 400 lanes, zero false permits, fixed/adaptive decision and permit parity in all 100 cases. |
| Blind retry duplicated the stage effect in the accepted drop-after-accept case. | Provider-shaped scripted lane: two release-labelled revisions, one promotion, one record. |
| Blind abort left the chain incomplete in that case. | Provider-shaped scripted lane: one staged revision, zero promotions, zero records; baseline revision still serving. |
| The direct live-cloud candidate failed closed before settlement. | Initial G5R pass was `UNKNOWN`; continuation and retry were denied; zero recovery-action permits were issued. |
| The settled live pass safely continued the exact chain. | One correlated revision, deterministic certificates, two `max_uses=1` permits, one promotion, and one Firestore record. |
| Permit replay was stopped before provider contact. | Replay outcome `REJECTED_BEFORE_PROVIDER_CONTACT`, contact delta zero. |

The live proof and scripted comparison answer different questions. The scripted
matrix compares policies under the same declared fault. The live G5R candidate
proves the recovery path against Google Cloud. It did not run live blind-retry,
blind-abort, or fixed comparison lanes.

## Withheld claims

- No claim that Gemini or adaptive planning outperforms the fixed planner. The
  scripted adaptive lane used 325 probes versus 370 fixed, with medians of 2 and
  2.5. The 20% median reduction missed the preregistered 25% threshold.
- No claim that model use reduced latency, tokens, or cost. Scripted model calls
  did not measure provider token or billing data.
- No general exactly-once guarantee. The accepted outcome is one exact bounded
  chain under durable identities, evidence rules, preconditions, and permit CAS.
- No claim that arbitrary MCP tools or every provider can be reconciled. A target
  needs stable semantic identity and authoritative read-after-write evidence.
- No claim that the checked-in JSON is the original transcript. It is a sanitized
  derivative whose values and immutable hashes come from the public gate record.
- No active hosted-service claim. The accepted deployment was ephemeral and its
  resources were cleaned up after evidence capture.

## Why this is not “just retry”

Retries answer *when should the caller try again?* RECONCILE first answers *what
did the provider already do?* An exact retry or continuation is available only
after deterministic evidence rules prove that action is safe.

## Relationship to prior art

- **Idempotency keys** are the first choice when a provider offers a durable key
  with well-defined replay semantics. RECONCILE helps when that contract is absent,
  partial, or does not cover a multi-step release chain.
- **Provider operation IDs and status APIs** are high-value evidence sources. They
  become inputs to the verifier, not substitutes for effect-specific checks.
- **Workflow engines, retries, and sagas** coordinate durable progress and
  compensation. RECONCILE supplies an evidence-backed decision at an ambiguous
  step before that workflow retries, continues, compensates, or holds.
- **Transactional outboxes, inboxes, and leases** protect boundaries an application
  controls. They cannot by themselves prove what an external provider accepted
  after the acknowledgement was lost.
- **Logs, traces, and observability** explain attempts. RECONCILE admits only facts
  that satisfy source, correlation, freshness, and effect rules before mutation.

## Trust and safety boundary

Gemini output is advisory and untrusted. It can propose a hypothesis and
allowlisted read-only probes. It cannot create a certificate, issue a permit, alter
permit scope, or cause provider contact. Stale, conflicting, insufficient, or
unavailable evidence produces an ambiguity witness and a hold.

The public fixture contains no credentials, access tokens, project secrets, or
private evidence locations. Hosted operators must keep raw provider artifacts and
identity material outside the repository.

## Current limitations

- **Target:** the accepted path is Cloud Run stage → traffic promotion → Firestore
  release record. New actions require explicit effects, probes, and verifier rules.
- **Provider:** recovery quality is bounded by authoritative, correlated provider
  reads. Unavailable or eventually inconsistent evidence can prolong `UNKNOWN`.
- **Portability:** the Phase 5 infrastructure is sealed to a maintainer-operated
  Google Cloud environment; it is not a turnkey deploy-to-any-project template.
- **Operations:** operator approval, budget controls, IAM preflight, evidence
  custody, cleanup, and provider degradation remain human responsibilities.
- **Cost:** Cloud Run, Firestore, Storage, Artifact Registry, logging, and Vertex AI
  can incur charges. The accepted deployment was torn down after one candidate.
- **Privacy:** provider responses and model prompts may include operational
  metadata. Production use needs retention, redaction, residency, and access rules.
- **Model availability:** provider failure never widens authority. The workflow
  fails closed or uses an explicitly configured deterministic route.
- **Public proof:** the public record exposes evidence hashes and a sanitized
  summary, not a private raw provider record or event transcript.

## Evidence index

- [Fresh provider proof](../demo/evidence/provider-proof.json)
- [Hash-linked live corroboration](../demo/evidence/live-corroboration.json)
- [Qualification artifacts](https://gist.github.com/OCHOLA-EDDYPHIL/c746539699b1a686f2e32f02fd4f740e)
- [Scripted qualification manifest](../demo/evidence/proof-to-permit.json)
