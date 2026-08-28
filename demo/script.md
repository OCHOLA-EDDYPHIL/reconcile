# Proof-to-Permit demo script

<!-- duration-seconds: 210 -->

Reference sequence length: 3 minutes 30 seconds. The screen cues navigate the
checked-in and public artifacts; they do not instruct a new provider run.

## 0:00–0:22 — The lost acknowledgement

**Screen:** Open `demo/proof.svg`, centered on the lost-acknowledgement fault.

**Narration:**

“An agent asks Cloud Run to stage a revision. Cloud Run accepts it, but the
response disappears. A timeout cannot tell the agent whether the change happened.
Retrying may duplicate the revision. Aborting may strand a real change. RECONCILE
does neither. Gemini investigates; deterministic evidence decides.”

## 0:22–0:45 — Make both baselines lose

**Screen:** Highlight the red scripted-fixture panel.

**Narration:**

“In the accepted provider-shaped drop-after-accept case, blind retry completed the
chain but created two release-labelled revisions. Blind abort made one revision,
then left it staged with zero promotions and zero release records. These are
scripted qualification results, not live-cloud comparison claims.”

## 0:45–1:15 — Fail closed first

**Screen:** Run:

```bash
uv run --no-sync python scripts/replay_gate_g5r.py
```

**Narration:**

“The offline validator next checks the checked-in provider evidence. Its first
recorded reconciliation pass cannot yet establish authoritative settlement. The
classifier returns UNKNOWN. CONTINUE is denied for insufficient evidence. RETRY
is denied because it risks a duplicate, and zero recovery-action permits are
issued. The safe answer is allowed to be ‘I do not know yet.’”

## 1:15–1:50 — Investigate, prove, permit

**Screen:** Open `docs/architecture.svg`; follow the advisory, evidence,
deterministic-authority, and guarded-action lanes.

**Narration:**

“RecoveryAgent invokes an ADK-backed Gemini 3.5 Flash planner to form one
evidence-cited hypothesis and propose allowlisted read-only probes. Gemini is not
the authority. The evidence layer checks source, freshness, and exact release
correlation. A
deterministic verifier alone creates a certificate. That certificate can mint
only the next exact permit, with an expiry and one use. Firestore arbitrates its
durable claim before the dispatcher contacts the provider.”

## 1:50–2:25 — Complete exactly the intended chain

**Screen:** Return to the terminal's validated direct-trace section; point to the
revision, permit, and effect lines.

**Narration:**

“After Cloud Run settles, the later pass observes one uniquely correlated revision
serving one hundred percent of traffic and classifies COMMITTED. One permit
promotes that exact revision. A second certified permit writes the release record.
The final provider counters are one revision, one promotion, and one Firestore
completion.”

## 2:25–2:47 — Attack the authority boundary

**Screen:** Point to `REJECTED_BEFORE_PROVIDER_CONTACT`.

**Narration:**

“Then the same consumed authority is presented again. The dispatch gate rejects it
before provider contact. Whole-request replay returns the identical durable
snapshot and creates no new work. A model can suggest an investigation, but it
cannot spend, widen, or replay a permit.”

## 2:47–3:00 — Show the hosted Google Cloud proof

**Screen:** Open the public
[provider proof](https://github.com/OCHOLA-EDDYPHIL/reconcile-proof-to-permit/releases/download/v0.1.1/provider-proof.json).
Find source `4d626bb67739ca51c7569124724ea5d7ac8f5c0e`, run
`p5r-adaptive-b166ba368d1cbc3e9ab57dee61b3dd74`, and the 49-event projection.

**Narration:**

“The fresh public provider proof identifies source
`4d626bb67739ca51c7569124724ea5d7ac8f5c0e`, run
`p5r-adaptive-b166ba368d1cbc3e9ab57dee61b3dd74`, and a 49-event projection. Its
run and revision identifiers bind this artifact to the recorded Google Cloud
execution. The same hash-linked record is checked in for offline validation.”

## 3:00–3:20 — Show the proof, not a promise

**Screen:** Run:

```bash
uv run --no-sync python scripts/check_release_candidate.py
```

**Narration:**

“The checked-in fixture validates frozen counts, classifications, certificate
hashes, permit limits, replay result, links, and the claim boundary. The fresh
provider record, live corroboration, cleanup verification, and checksums are in
the public evidence release. The cloud resources were cleaned up after capture,
so this is offline evidence-fixture validation, not an active service.”

## 3:20–3:30 — Close

**Screen:** Return to the title in `README.md`.

**Narration:**

“RECONCILE turns ‘the call failed’ into a safer question: what did the world
actually do, and what exact action is now permitted?”
