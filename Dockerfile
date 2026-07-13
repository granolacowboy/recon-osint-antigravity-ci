# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.13.14-slim-trixie@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

FROM ${PYTHON_IMAGE} AS dependencies

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    VIRTUAL_ENV=/opt/venv

RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /build
COPY requirements.txt ./requirements.txt
RUN python -m pip install --requirement requirements.txt


FROM ${PYTHON_IMAGE} AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

# The base digest predates these Debian security revisions. Pinning each
# upgraded package keeps the resulting runtime deterministic and makes a
# missing repository revision fail the build instead of silently drifting.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade \
        base-files=13.8+deb13u6 \
        liblzma5=5.8.1-1+deb13u1 \
        libssl3t64=3.5.6-1~deb13u2 \
        openssl-provider-legacy=3.5.6-1~deb13u2 \
        openssl=3.5.6-1~deb13u2 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 recon \
    && useradd --uid 10001 --gid recon --no-create-home --shell /usr/sbin/nologin recon

WORKDIR /app
COPY --from=dependencies /opt/venv /opt/venv
COPY --chown=recon:recon app ./app
COPY --chown=recon:recon scripts/container_checks.py ./scripts/container_checks.py

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python", "/app/scripts/container_checks.py", "api"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
