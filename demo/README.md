# Demo candidate

This bundle is the recording-ready Proof-to-Permit story. It is tied to the exact
G5R candidate and keeps scripted comparison evidence separate from direct-cloud
operational proof.

## Run it

```bash
uv run --no-sync python scripts/replay_gate_g5r.py
uv run --no-sync python scripts/check_release_candidate.py
```

For machine-readable output:

```bash
uv run --no-sync python scripts/replay_gate_g5r.py --json
```

The replay validates [evidence/proof-to-permit.json](evidence/proof-to-permit.json)
before printing anything. It refuses changed counts, hashes, classifications,
claim authorization, permit cardinality, replay behavior, or cleanup inventory.

## Evidence layers

| Panel | What it demonstrates | What it does not demonstrate |
| --- | --- | --- |
| Accepted scripted baseline | Under the same provider-shaped drop-after-accept fixture, blind retry creates two revisions and blind abort leaves the chain incomplete. | A live Google Cloud A/B test. |
| Direct live-cloud G5R trace | Gemini hypothesis, initial fail-closed result, later correlated revision, deterministic certificate, exact permits, effects `1/1/1`, and replay denial. | Adaptive superiority, measured efficiency, or an active public endpoint. |

Use [proof.svg](proof.svg) as the opening comparison visual and
[../docs/architecture.svg](../docs/architecture.svg) for the authority walkthrough.
Both have checked-in Graphviz sources.

## Recording packet

- [script.md](script.md) — timed narration and exact screen actions
- [proof.svg](proof.svg) — baseline-versus-live hero visual
- [../docs/architecture.svg](../docs/architecture.svg) — numbered architecture
- [evidence/proof-to-permit.json](evidence/proof-to-permit.json) — sanitized proof
- [../devpost-submission.md](../devpost-submission.md) — local submission-copy draft

## Rehearsal acceptance

- [ ] Start from a clean checkout and complete the locked install.
- [ ] Run both commands above with no cloud credentials in the checkout.
- [ ] Keep “scripted baseline” and “direct live-cloud trace” labels visible.
- [ ] Show `UNKNOWN` and both denied actions before any permit.
- [ ] Show the exact correlated revision and both single-use permits.
- [ ] Show `1/1/1` and replay rejection before provider contact.
- [ ] State that the deployment was cleaned up and no public endpoint exists.
- [ ] If a live provider is unavailable, use the accepted evidence replay; do not
      improvise a new cloud candidate during recording.
- [ ] Check every public link in a private/incognito browser before publication.
- [ ] Keep the final recording at or below four minutes.

Publication, upload, release creation, and external submission remain separate
owner-authorized actions.
