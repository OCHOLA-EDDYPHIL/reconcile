# Hosted recovery runbook

This runbook describes the maintainer-operated path for an authorized Google
Cloud environment. The recorded environment was ephemeral and was removed after
evidence capture.

## What is portable and what is sealed

Application contracts, the container, evidence rules, and the operator state
machine are in the repository. Environment identity enters through one strict
deployment profile outside the checkout. A current v2 profile contains exactly
`schema_version`, `project_id`, `project_number`, `billing_account_id`,
`owner_account`, `operating_profile`, and `notification_channel_ids`. The
operator derives service identities, audiences, buckets, and backend
configuration from those values. Legacy v1 profiles remain valid only as
disposable evidence profiles.

The input must be canonical JSON in an absolute, owner-only `0600` regular file.
`prepare-artifacts` rejects symlinks, placeholders, duplicate or extra fields,
and files inside the repository. It seals a canonical `0400` copy and the three
Terraform backend configurations in the private operator state directory, then
binds them into the manifest. Do not commit the profile, backend configuration,
or operator state.

## Prerequisites

- An exact clean source revision and reviewed `uv.lock`
- Python 3.12.13 and uv 0.12.3
- Terraform 1.15.8 with Google provider 7.44.0
- Docker 29.6.2 and Google Cloud CLI 580.0.0
- A dedicated Google Cloud project and billing account with an approved budget
- An external deployment profile matching that project and the active owner
- Application Default Credentials for an operator allowed to impersonate the
  reviewed apply identity
- Required Google APIs, Cloud Run, Firestore databases, Artifact Registry,
  Storage buckets, and service accounts provisioned from reviewed plans
- Explicit approval bound to the exact manifest, source, image, infrastructure,
  semantic configuration, budget, and work window

Never commit credentials or raw operator state. Use an operator-owned directory
outside the checkout and an external secret store.

The `evidence` profile forbids notification channels and keeps resources sized
for a disposable acceptance run. The `production` profile requires at least one
project-local notification channel. It enables data and service deletion
protection, Firestore point-in-time recovery, object versioning and retention,
and bounded multi-instance API and controller capacity. Production rejects
acceptance-only fault injection. The deployment identity provisions resources;
a separate operator identity has only authenticated API invocation authority.

## Sealed operator sequence

Discover the interface without mutating cloud state:

```bash
uv run --no-sync python scripts/phase5_operator.py --help
uv run --no-sync python scripts/phase5_operator.py inspect \
  --state-dir <operator-state>
```

The state machine is:

1. `prepare-artifacts --deployment-profile <absolute-path>` seals the external
   environment identity and records toolchain, source, dependency, container,
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
export RECONCILE_DEPLOYMENT_PROFILE="<absolute-path-to-sealed-deployment-profile>"

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
3. Deterministic verification issues the exact hash-bound certificate and
   `max_uses=1` permit for each continuation.
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
[provider evidence record](../evidence/v0.2.0/provider-proof.json). Teardown
evidence and the zero-resource inventory are in
[cleanup verification](../evidence/v0.2.0/cleanup-verification.json).

For a new accepted revision, capture the fixed post-teardown inventory from the
sealed manifest and export only after the capture returns `PASS`. A non-empty
inventory returns `RESOURCES_REMAIN` with a nonzero exit status; wait for cloud
state to converge and capture again to a new path.

```bash
uv run --no-sync python -m scripts.capture_post_teardown_inventory \
  --manifest <operator-state>/manifest-<manifest-id>.json \
  --output <private-output>/post-teardown-inventory.json

uv run --no-sync python -m scripts.export_public_evidence \
  --provider-acceptance <provider-acceptance-record> \
  --hosted-acceptance <hosted-acceptance-record> \
  --runtime-teardown-evidence <runtime-teardown-record> \
  --foundation-teardown-evidence <foundation-teardown-record> \
  --state-protection-evidence <state-protection-record> \
  --bootstrap-teardown-evidence <bootstrap-teardown-record> \
  --post-teardown-inventory <private-output>/post-teardown-inventory.json \
  --output <private-output>/public-evidence/v0.2.0
```

The exporter accepts one exact provider record, one exact hosted record, and
the four successful teardown records bound to the same manifest. It emits only
the sanitized four-file public bundle and refuses mismatched custody chains.

## Static viewer boundary

The optional viewer is built from a validated versioned evidence directory. Its
bundle records the viewer source revision separately from the evidence source
revision. The exporter requires a clean exact-main checkout and stages runtime
files from that verified commit. The viewer serves only immutable HTML and JSON
over `GET` and `HEAD`; its dedicated service account has no operational roles,
and the application makes no outbound calls to recovery services or provider
targets.

Build and lifecycle approval for a viewer deployment are separate from the
operational recovery environment. Retaining a viewer does not retain the core
services or expand the authority of the recorded evidence.

The evidence directory, generated bundle, and Docker build context must all be
outside the checkout, and each output path must not exist before the command
that creates it. Stage and build the exact validated projection as follows:

```bash
PUBLIC_EVIDENCE=/absolute/path/outside-repo/public-evidence/v0.2.0
VIEWER_BUNDLE=/absolute/path/outside-repo/viewer-bundle
VIEWER_CONTEXT=/absolute/path/outside-repo/viewer-context

uv run --no-sync python -m viewer.export \
  --evidence "$PUBLIC_EVIDENCE" \
  --output "$VIEWER_BUNDLE" \
  --build-context-output "$VIEWER_CONTEXT"

VIEWER_SOURCE_REVISION="$(uv run --no-sync python -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["viewer_source_revision"])' \
  "$VIEWER_BUNDLE/snapshot.json")"
EVIDENCE_SOURCE_REVISION="$(uv run --no-sync python -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["evidence_source_revision"])' \
  "$VIEWER_BUNDLE/snapshot.json")"
SNAPSHOT_SHA256="$(sha256sum "$VIEWER_BUNDLE/snapshot.json" | awk '{print $1}')"
```

Use a pre-created Artifact Registry repository and a dedicated runtime service
account with no operational Reconcile roles. Build, push, resolve the immutable
image digest, and deploy only that digest:

```bash
VIEWER_PROJECT=<viewer-project-id>
VIEWER_REGION=us-central1
VIEWER_REPOSITORY=<artifact-registry-repository>
VIEWER_SERVICE=reconcile-evidence
VIEWER_SERVICE_ACCOUNT=<viewer-service-account-email>
VIEWER_IMAGE_URI="${VIEWER_REGION}-docker.pkg.dev/${VIEWER_PROJECT}/${VIEWER_REPOSITORY}/reconcile-viewer"
VIEWER_IMAGE_TAG="${VIEWER_IMAGE_URI}:${VIEWER_SOURCE_REVISION}"

gcloud auth configure-docker "${VIEWER_REGION}-docker.pkg.dev"
docker build \
  --file "$VIEWER_CONTEXT/Dockerfile" \
  --build-arg VIEWER_SOURCE_REVISION="$VIEWER_SOURCE_REVISION" \
  --build-arg EVIDENCE_SOURCE_REVISION="$EVIDENCE_SOURCE_REVISION" \
  --build-arg SNAPSHOT_SHA256="$SNAPSHOT_SHA256" \
  --tag "$VIEWER_IMAGE_TAG" \
  "$VIEWER_CONTEXT"
docker push "$VIEWER_IMAGE_TAG"

VIEWER_IMAGE_DIGEST="$(gcloud artifacts docker images describe \
  "$VIEWER_IMAGE_TAG" \
  --project "$VIEWER_PROJECT" \
  --format='value(image_summary.digest)')"

gcloud run deploy "$VIEWER_SERVICE" \
  --project "$VIEWER_PROJECT" \
  --region "$VIEWER_REGION" \
  --image "${VIEWER_IMAGE_URI}@${VIEWER_IMAGE_DIGEST}" \
  --service-account "$VIEWER_SERVICE_ACCOUNT" \
  --allow-unauthenticated \
  --ingress all \
  --port 8080 \
  --cpu 1 \
  --memory 256Mi \
  --min-instances 0 \
  --max-instances 2 \
  --concurrency 80 \
  --timeout 30s

gcloud run services describe "$VIEWER_SERVICE" \
  --project "$VIEWER_PROJECT" \
  --region "$VIEWER_REGION" \
  --format='value(status.url)'
```

## Published evidence verification

Build the tagged release from the exact tag before publication. After the
release assets and retained viewer are public, verify their shared source and
evidence identities, every downloaded byte, the viewer projection, security
headers, read-only routes, and rejected mutation methods:

```bash
uv run --no-sync python scripts/verify_publication.py \
  --release-directory <downloaded-release-directory> \
  --version v0.2.0 \
  --viewer-url https://reconcile-evidence-g6fwwrme5a-uc.a.run.app
```
