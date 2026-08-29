ARG PYTHON_IMAGE=python:3.12.13-slim-bookworm@sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af

FROM ${PYTHON_IMAGE}
ARG VIEWER_SOURCE_REVISION
ARG EVIDENCE_SOURCE_REVISION
ARG SNAPSHOT_SHA256
LABEL org.opencontainers.image.source="https://github.com/OCHOLA-EDDYPHIL/reconcile" \
      org.opencontainers.image.revision="${VIEWER_SOURCE_REVISION}" \
      org.opencontainers.image.title="RECONCILE evidence viewer" \
      reconcile.evidence.source-revision="${EVIDENCE_SOURCE_REVISION}" \
      reconcile.evidence.snapshot="${SNAPSHOT_SHA256}"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RECONCILE_VIEWER_BUNDLE=/app/bundle
WORKDIR /app
COPY --chmod=0444 server.py public_contract.py /app/
COPY --chmod=0444 bundle/index.html /app/bundle/index.html
COPY --chmod=0444 bundle/snapshot.json /app/bundle/snapshot.json
COPY --chmod=0444 bundle/bundle-manifest.json /app/bundle/bundle-manifest.json
RUN test "${#VIEWER_SOURCE_REVISION}" -eq 40 \
    && case "${VIEWER_SOURCE_REVISION}" in *[!0-9a-f]*) exit 1 ;; esac \
    && test "${#EVIDENCE_SOURCE_REVISION}" -eq 40 \
    && case "${EVIDENCE_SOURCE_REVISION}" in *[!0-9a-f]*) exit 1 ;; esac \
    && test "${#SNAPSHOT_SHA256}" -eq 64 \
    && case "${SNAPSHOT_SHA256}" in *[!0-9a-f]*) exit 1 ;; esac \
    && printf '%s  %s\n' "${SNAPSHOT_SHA256}" /app/bundle/snapshot.json \
      | sha256sum --check --strict \
    && VIEWER_SOURCE_REVISION="${VIEWER_SOURCE_REVISION}" \
       EVIDENCE_SOURCE_REVISION="${EVIDENCE_SOURCE_REVISION}" \
       python -c 'import os; from pathlib import Path; from public_contract import decode_snapshot; from server import load_bundle; snapshot = decode_snapshot(load_bundle(Path("/app/bundle"))["/snapshot.json"][0]); raise SystemExit(snapshot["viewer_source_revision"] != os.environ["VIEWER_SOURCE_REVISION"] or snapshot["evidence_source_revision"] != os.environ["EVIDENCE_SOURCE_REVISION"])' \
    && chmod 0555 /app /app/bundle
ENV RECONCILE_SNAPSHOT_SHA256=${SNAPSHOT_SHA256} \
    RECONCILE_VIEWER_SOURCE_REVISION=${VIEWER_SOURCE_REVISION} \
    RECONCILE_EVIDENCE_SOURCE_REVISION=${EVIDENCE_SOURCE_REVISION}
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "/app/server.py"]
