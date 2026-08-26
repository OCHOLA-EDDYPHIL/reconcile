# Proof-to-Permit demo script

<!-- duration-seconds: 210 -->

Target recording length: 3 minutes 30 seconds. Keep the terminal at a readable
font size and use the exact commands shown here.

## 0:00–0:22 — The lost acknowledgement

**Screen:** Open `demo/proof.svg`, centered on the left-hand fault.

**Narration:**

“An agent asks Cloud Run to stage a revision. Cloud Run accepts it, but the
response disappears. A timeout cannot tell the agent whether the change happened.
Retrying may duplicate the revision. Aborting may strand a real change. RECONCILE
does neither. Gemini investigates; deterministic evidence decides.”

## 0:22–0:45 — Make both baselines lose

**Screen:** Highlight the red scripted-baseline panel.

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

“Now the direct Google Cloud candidate. The first reconciliation pass sees the
exact revision response, but not yet authoritative traffic and effect settlement.
The classifier returns UNKNOWN. CONTINUE is denied for insufficient evidence.
RETRY is denied because it risks a duplicate. No permit, promotion, or Firestore
record exists. The safe answer is allowed to be ‘I do not know yet.’”

## 1:15–1:50 — Investigate, prove, permit

**Screen:** Open `docs/architecture.svg`; follow steps 4 through 8.

**Narration:**

“RecoveryAgent invokes an ADK-backed Gemini 3.5 Flash planner to form one
evidence-cited hypothesis and propose allowlisted read-only probes. Gemini is not
the authority. The evidence layer checks source, freshness, and exact release
correlation. A
deterministic verifier alone creates a certificate. That certificate can mint
only the next exact permit, with an expiry and one use. Firestore arbitrates its
durable claim before the dispatcher contacts the provider.”

## 1:50–2:25 — Complete exactly the intended chain

**Screen:** Return to the terminal's live-trace section; point to the revision,
permit, and effect lines.

**Narration:**

“After Cloud Run settles, the later pass observes one uniquely correlated revision,
matching generation, terminal success, and unchanged pre-promotion traffic. It
classifies COMMITTED. One permit promotes that exact revision. A second certified
permit writes the release record. The final provider counters are one revision,
one promotion, and one Firestore completion. The revision serves one hundred
percent of traffic.”

## 2:25–2:47 — Attack the authority boundary

**Screen:** Point to `REJECTED_BEFORE_PROVIDER_CONTACT`.

**Narration:**

“Then the same consumed authority is presented again. The dispatch gate rejects it
before provider contact. Whole-request replay returns the identical durable
snapshot and creates no new work. A model can suggest an investigation, but it
cannot spend, widen, or replay a permit.”

## 2:47–3:00 — Show the hosted Google Cloud proof

**Screen:** Show a sanitized Google Cloud Logs Explorer capture from the accepted
run, filtered to `run_id="p5r-adaptive-9b53f92fcb05d60fabe3e1a5301ba402"`.
Point to the Cloud Run service, revision, and timestamp that match the checked-in
evidence. Keep project, account, and unrelated log fields hidden.

**Narration:**

“This Logs Explorer record is from the accepted hosted run. Its run and revision
identifiers match the immutable evidence, tying the replay to backend execution
on Google Cloud.”

## 3:00–3:20 — Show the proof, not a promise

**Screen:** Run:

```bash
uv run --no-sync python scripts/check_release_candidate.py
```

**Narration:**

“The checked-in fixture validates the frozen counts, classifications, certificate
hashes, permit limits, replay result, links, and claim boundary. The original
live record is linked by immutable hashes. The cloud resources were cleaned up
after capture, so this is a reproducible evidence replay, not an active service.”

## 3:20–3:30 — Close

**Screen:** Return to the title in `README.md`.

**Narration:**

“RECONCILE turns ‘the call failed’ into a safer question: what did the world
actually do, and what exact action is now permitted?”
