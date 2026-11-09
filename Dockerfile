# syntax=docker/dockerfile:1.7
# ThreatLens container image. Multi-stage: build deps never reach the runtime image.

ARG PYTHON_IMAGE=python:3.13.18-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490

# ---------------------------------------------------------------- build stage
FROM ${UV_IMAGE} AS uv
FROM ${PYTHON_IMAGE} AS build

COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/threatlens

WORKDIR /src
# Dependencies first (cached layer), then the project itself.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY README.md LICENSE ./
COPY src ./src
COPY rules/examples ./rules/examples
COPY tests/rules ./tests/rules
RUN uv sync --locked --no-dev --no-editable \
 && find /opt/threatlens -name "*.pyi" -delete \
 && rm -rf /opt/threatlens/lib/python3.13/site-packages/pip* /opt/threatlens/bin/pip*

# ---------------------------------------------------------------- runtime stage
FROM ${PYTHON_IMAGE} AS runtime

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="ThreatLens" \
      org.opencontainers.image.description="Lightweight self-hosted detection & investigation platform (mini-SIEM) built on Sigma rules" \
      org.opencontainers.image.source="https://github.com/Tamimsharif83/threatlens" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# Security updates for the base OS, and remove pip/ensurepip from the system Python:
# ThreatLens never installs packages at runtime, and pip's vendored libraries
# (urllib3, msgpack, ...) are frequent sources of scanner findings.
# Then an unprivileged user with a fixed UID/GID; /data is the only writable path.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt /var/log/dpkg.log \
 && rm -rf /usr/local/lib/python3.13/site-packages/pip \
           /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.13/ensurepip \
           /usr/local/bin/pip /usr/local/bin/pip3* \
 && groupadd --system --gid 10001 threatlens \
 && useradd --system --uid 10001 --gid threatlens --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin threatlens \
 && mkdir -p /data \
 && chown threatlens:threatlens /data \
 && chmod 0700 /data

COPY --from=build /opt/threatlens /opt/threatlens

ENV PATH=/opt/threatlens/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TL_HOST=0.0.0.0 \
    TL_PORT=8080 \
    TL_DATA_DIR=/data \
    TMPDIR=/data/tmp

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["threatlens", "healthcheck"]

ENTRYPOINT ["threatlens"]
CMD ["serve"]
