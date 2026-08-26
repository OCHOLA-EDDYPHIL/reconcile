# Title

RECONCILE — Proof Before Retry

## One-line Summary

RECONCILE prevents agents from guessing after ambiguous tool failures: Gemini
investigates, deterministic evidence decides, and exact single-use permits control
the next mutation.

## Problem

A timeout says the response failed, not that the real-world action failed. If an
agent blindly retries an accepted payment, deployment, ticket, or database change,
it can duplicate the effect. If it blindly aborts, it can abandon committed work.
Most agent runtimes expose retries and logs but do not establish what the provider
already did before authorizing the next side effect.

## Solution

RECONCILE wraps ambiguous effects in a Proof-to-Permit workflow. It records the
intended action and durable dispatch receipt, uses Gemini to propose a bounded
investigation, admits only fresh and correlated provider facts, and applies
deterministic effect rules. Proven state yields a certificate and an expiring
`max_uses=1` permit for one exact continuation or retry. Insufficient or conflicting
evidence yields an ambiguity witness and no mutation.

The accepted Google Cloud chain stages one Cloud Run revision, promotes that exact
revision, and creates one Firestore release record.

## Why This Matters

Agent reliability cannot stop at “the API call threw an exception.” Consequential
automation needs an authority boundary between reasoning about what may have
happened and permission to change the world again. RECONCILE makes that boundary
durable, inspectable, and fail-closed.

In the accepted scripted drop-after-accept case, blind retry created two revisions
and blind abort left the chain incomplete. In the separate direct-cloud trace,
RECONCILE held the initial ambiguity, later proved the exact revision, performed
one promotion and one Firestore completion, and rejected permit replay before
provider contact.

## How We Used AI

Gemini 3.5 Flash, accessed through Vertex AI and orchestrated with Google ADK,
generates an evidence-cited hypothesis and proposes allowlisted read-only probes.
It is deliberately not the proof authority. Deterministic code validates source,
freshness, correlation, declared effects, and transition preconditions before any
certificate or permit can exist.

This division makes the model useful where uncertainty is high while keeping the
mutation boundary predictable and testable.

## How We Used Codex

Codex supported issue-first planning, implementation review, focused local checks,
live-cloud evidence analysis, IAM fault isolation, acceptance-record preparation,
and release-candidate packaging. The workflow kept source changes, cloud actions,
claim wording, tracker state, and cleanup evidence tied to explicit acceptance
contracts rather than treating generated text as authority.

## Key Features

- Two-agent ADK workflow: `RolloutAgent` and `RecoveryAgent`
- Gemini hypothesis generation with bounded read-only provider probes
- Deterministic `COMMITTED`, `PENDING`, `FAILED`, and `UNKNOWN` evidence rules
- Verified certificates or explicit ambiguity witnesses
- Exact semantic-action permits with expiry and `max_uses=1`
- Firestore-backed durable claims, provider ledger, run state, and release record
- Replay rejection before provider contact
- CLI, API, event timeline, JSON schemas, and immutable evidence hashes
- Blind retry, blind abort, fixed, and adaptive policy comparison harness

## Architecture

`RolloutAgent → dispatch gate → Cloud Run → lost acknowledgement → RecoveryAgent +
Gemini → allowlisted provider reads → deterministic verifier → certificate or
witness → Firestore permit CAS → exact continuation → Cloud Run + Firestore`

Diagram: `docs/architecture.svg`

Google Cloud roles:

- Vertex AI / Gemini: advisory investigation
- Google ADK: agent orchestration
- Cloud Run: hosted services and mutation target
- Firestore: durable recovery, permit, ledger, and completion state
- Cloud Storage: sealed operator and infrastructure artifacts
- IAM: separated read and mutation identities

## Testing Instructions

```bash
git clone https://github.com/OCHOLA-EDDYPHIL/reconcile.git
cd reconcile
uv sync --locked --all-groups
uv run --no-sync python scripts/replay_gate_g5r.py
uv run --no-sync python scripts/check_release_candidate.py
```

Expected result: both commands end in `PASS`. The first distinguishes accepted
scripted baseline evidence from the direct live-cloud G5R trace. The second checks
the frozen evidence invariants, local links, private-path boundary, claim language,
demo duration, and diagram exports.

## Public Demo Link

**PENDING PUBLICATION.** The accepted cloud environment was cleaned up; there is
no current public endpoint. Canonical live evidence:
https://github.com/OCHOLA-EDDYPHIL/reconcile/issues/173#issuecomment-5427414445

## Public Repository Link

https://github.com/OCHOLA-EDDYPHIL/reconcile

## Demo Video

**PENDING RECORDING/UPLOAD.** Recording-ready script: `demo/script.md`.
Target runtime: 3:45; maximum: 4:00.

## Screenshot Shot List

1. `demo/proof.svg`: lost acknowledgement and losing baselines
2. Terminal: initial `UNKNOWN`, denied continuation/retry, zero permits
3. `docs/architecture.svg`: Gemini advisory versus deterministic authority
4. Terminal: correlated revision, exact permit chain, effects `1/1/1`
5. Terminal: replay rejected before provider contact
6. GitHub acceptance record: exact source, hashes, and zero-resource cleanup

## Submission Readiness Notes

- README, architecture source/SVG, hosted runbook, claim boundary, sanitized proof,
  demo visual, timed narration, rehearsal checklist, and testing instructions exist.
- Gate G5R is accepted at source
  `7f64cda91de7d0404f4673a818352e296a1a817e`.
- Release publication, video upload, public demo provisioning, official form
  validation, and external submission are not authorized by this draft.
- Official event requirements and form-specific copy have not been fetched through
  an authenticated Devpost workflow.

## Known Limitations

- The accepted target is one Cloud Run-to-Firestore release chain, not arbitrary
  tool reconciliation.
- The scripted baseline comparison is not a live-cloud A/B test.
- Adaptive efficiency and model superiority are not authorized claims.
- The public fixture is a sanitized derivative, not the private raw transcript.
- The maintainer infrastructure is sealed to one environment and is not turnkey.
- Provider unavailability or weak evidence can prolong `UNKNOWN`; that is an
  intentional safe outcome.
- The accepted live deployment was ephemeral and has been cleaned up.

## TODO Official Form Fields

- Confirm the official hackathon and exact form requirements through Devpost.
- Add the final public demo URL if a separately authorized environment is created.
- Add the final public video URL after recording and upload authorization.
- Confirm repository visibility, license choice, team fields, categories, and
  sponsor-technology checkboxes.
- Add a Codex session ID only if the official form asks for one and the owner
  confirms the correct project session.
