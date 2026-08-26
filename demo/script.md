# Proof-to-Permit demo script

<!-- duration-seconds: 225 -->

Target recording length: 3 minutes 45 seconds. Keep the terminal at a readable
font size and use the exact commands shown here.

## 0:00–0:25 — The lost acknowledgement

**Screen:** Open `demo/proof.svg`, centered on the left-hand fault.

**Narration:**

“An agent asks Cloud Run to stage a revision. Cloud Run accepts it, but the
response disappears. A timeout cannot tell the agent whether the change happened.
Retrying may duplicate the revision. Aborting may strand a real change. RECONCILE
does neither. Gemini investigates; deterministic evidence decides.”

## 0:25–0:55 — Make both baselines lose

**Screen:** Highlight the red scripted-baseline panel.

**Narration:**

“In the accepted provider-shaped drop-after-accept case, blind retry completed the
chain but created two release-labelled revisions. Blind abort made one revision,
then left it staged with zero promotions and zero release records. These are
scripted qualification results, not live-cloud comparison claims.”

## 0:55–1:30 — Fail closed first

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

## 1:30–2:10 — Investigate, prove, permit

**Screen:** Open `docs/architecture.svg`; follow steps 4 through 8.

**Narration:**

“RecoveryAgent uses Google ADK and Gemini 3.5 Flash to form one evidence-cited
hypothesis and propose allowlisted read-only probes. Gemini is not the judge. The
evidence layer checks source, freshness, and exact release correlation. A
deterministic verifier alone creates a certificate. That certificate can mint
only the next exact permit, with an expiry and one use. Firestore arbitrates its
durable claim before the dispatcher contacts the provider.”

## 2:10–2:50 — Complete exactly the intended chain

**Screen:** Return to the terminal's live-trace section; point to the revision,
permit, and effect lines.

**Narration:**

“After Cloud Run settles, the later pass observes one uniquely correlated revision,
matching generation, terminal success, and unchanged pre-promotion traffic. It
classifies COMMITTED. One permit promotes that exact revision. A second certified
permit writes the release record. The final provider counters are one revision,
one promotion, and one Firestore completion. The revision serves one hundred
percent of traffic.”

## 2:50–3:15 — Attack the authority boundary

**Screen:** Point to `REJECTED_BEFORE_PROVIDER_CONTACT`.

**Narration:**

“Then the same consumed authority is presented again. The dispatch gate rejects it
before provider contact. Whole-request replay returns the identical durable
snapshot and creates no new work. A model can suggest an investigation, but it
cannot spend, widen, or replay a permit.”

## 3:15–3:35 — Show the proof, not a promise

**Screen:** Run:

```bash
uv run --no-sync python scripts/check_release_candidate.py
```

**Narration:**

“The public fixture validates the frozen counts, classifications, certificate
hashes, permit limits, replay result, links, and claim boundary. The original
live record is linked by immutable hashes. After capture, the cloud resources were
cleaned up, so this is a reproducible evidence replay—not a pretend live endpoint.”

## 3:35–3:45 — Close

**Screen:** Return to the title in `README.md`.

**Narration:**

“RECONCILE turns ‘the call failed’ into a safer question: what did the world
actually do, and what exact action is now permitted?”
