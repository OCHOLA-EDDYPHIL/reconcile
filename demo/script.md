# RECONCILE demo script

<!-- duration-seconds: 210 -->

Reference sequence length: 3 minutes 30 seconds. The screen cues use checked-in
and published artifacts; they do not instruct a new provider run.

## 0:00–0:22 — The lost acknowledgement

**Screen:** Open `demo/proof.png`, centered on the lost-acknowledgement fault.

**Narration:**

“An agent asks Cloud Run to stage a revision. Cloud Run accepts it, but the
response disappears. A timeout cannot tell the agent whether the change happened.
Retrying may duplicate the revision. Aborting may strand a real change. RECONCILE
does neither. Gemini investigates; deterministic evidence decides.”

## 0:22–0:45 — Make both baselines lose

**Screen:** Highlight the red scripted-fixture panel.

**Narration:**

“In the provider-shaped drop-after-accept fixture, blind retry completed the
chain but created two revisions. Blind abort made one revision, then left it
staged with zero promotions and zero release records. These are scripted
qualification results, not live-cloud comparison claims.”

## 0:45–1:15 — Fail closed first

**Screen:** Run:

```bash
uv run --no-sync python scripts/validate_evidence.py
```

**Narration:**

“The offline validator checks the evidence bundle. Its first recorded recovery
pass cannot establish authoritative settlement. The classifier returns UNKNOWN.
CONTINUE and RETRY are denied, and no recovery-action permit is issued. The safe
answer is allowed to be ‘I do not know yet.’”

## 1:15–1:50 — Investigate, verify, permit

**Screen:** Open `docs/architecture.png`, then `docs/deployment.png`; follow the
advisory, evidence, authority, identity, and guarded-action boundaries.

**Narration:**

“RecoveryAgent uses an ADK-backed Gemini 3.5 Flash planner to form one
evidence-cited hypothesis and propose allowlisted read-only probes. Gemini is not
the authority. Evidence admission checks source, freshness, and exact release
correlation. A deterministic verifier alone creates a certificate. That
certificate can mint only the next exact permit, with an expiry and one use.
Firestore claims it before the dispatcher contacts the provider.”

## 1:50–2:25 — Complete the intended chain

**Screen:** Return to the terminal summary and point to the revision, permit, and
effect lines.

**Narration:**

“After Cloud Run settles, the later pass observes one uniquely correlated
revision serving all traffic and classifies COMMITTED. One permit promotes that
exact revision. A second certified permit writes the release record. The final
provider counters are one revision, one promotion, and one Firestore completion.”

## 2:25–2:47 — Attack the authority boundary

**Screen:** Point to `REJECTED_BEFORE_PROVIDER_CONTACT`.

**Narration:**

“The same consumed authority is presented again. The dispatch gate rejects it
before provider contact. Whole-request replay returns the same durable snapshot
and creates no new work. A model can suggest an investigation, but it cannot
spend, widen, or replay a permit.”

## 2:47–3:00 — Inspect the provider evidence record

**Screen:** Open the published
[provider evidence record](https://github.com/OCHOLA-EDDYPHIL/reconcile/releases/download/v0.1.0/provider-proof.json).

**Narration:**

“The sanitized record includes source, run, revision, event, and hash fields that
bind it to the recorded Google Cloud execution. The same hash-linked bytes are
checked in for offline validation.”

## 3:00–3:20 — Validate the package

**Screen:** Run:

```bash
uv run --no-sync python scripts/check_release_candidate.py
```

**Narration:**

“The package check validates classifications, counts, certificate hashes, permit
limits, replay behavior, links, diagrams, and the claim boundary. Provider
evidence, corroboration, cleanup verification, and checksums are published
together. The recorded cloud resources were removed after capture, so this is
offline evidence validation, not an active service.”

## 3:20–3:30 — Close

**Screen:** Return to the title in `README.md`.

**Narration:**

“RECONCILE turns ‘the call failed’ into a safer question: what did the world
actually do, and what exact action is now permitted?”
