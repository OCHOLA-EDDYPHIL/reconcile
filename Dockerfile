ARG PYTHON_IMAGE=python:3.12.13-slim-bookworm@sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af
ARG UV_IMAGE=ghcr.io/astral-sh/uv@sha256:dfd1e6972e100ca2fbf1f391effc3dd4aa57f319bf03c3e321e0a3f3341ed5af

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS builder
ARG SOURCE_DATE_EPOCH
ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_COMPILE_BYTECODE=0 \
    UV_LINK_MODE=copy \
    UV_NO_PROGRESS=1 \
    UV_PROJECT_ENVIRONMENT=/opt/reconcile \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
COPY reconcile ./reconcile
RUN set -eu; \
    uv sync --locked --no-dev --no-editable; \
    metadata=/opt/reconcile/lib/python3.12/site-packages/reconcile-0.2.0.dist-info; \
    record="$metadata/RECORD"; \
    cache="$metadata/uv_cache.json"; \
    test -f "$cache"; \
    test "$(grep -F -c 'reconcile-0.2.0.dist-info/uv_cache.json,' "$record")" = 1; \
    rm "$cache"; \
    sed -i '/^reconcile-0[.]2[.]0[.]dist-info\/uv_cache[.]json,/d' "$record"

FROM ${PYTHON_IMAGE} AS runtime
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.source="https://github.com/OCHOLA-EDDYPHIL/reconcile" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.version="0.2.0"
ENV HOME=/tmp \
    PATH=/opt/reconcile/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY --from=builder --chown=65532:65532 /opt/reconcile /opt/reconcile
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/opt/reconcile/bin/python", "-m", "reconcile.hosted"]
