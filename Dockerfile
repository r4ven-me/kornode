# syntax=docker/dockerfile:1.7

ARG DEBIAN_VERSION=13
ARG DEBIAN_CODENAME=trixie
ARG OCSERV_VERSION=1.5.0
# SHA-256 of ocserv-${OCSERV_VERSION}.tar.xz. When set, the build refuses a
# tarball that doesn't match; update it together with OCSERV_VERSION.
ARG OCSERV_SHA256=

FROM debian:${DEBIAN_VERSION}-slim AS ocserv-builder

ARG DEBIAN_CODENAME
ARG OCSERV_VERSION
ARG OCSERV_SHA256

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

RUN rm -f /etc/apt/apt.conf.d/docker-clean \
    && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' \
      > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=tmpfs,target=/var/log \
    --mount=type=tmpfs,target=/var/tmp \
    --mount=type=tmpfs,target=/tmp \
    apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests \
      autoconf \
      automake \
      build-essential \
      ca-certificates \
      curl \
      gawk \
      gettext \
      git \
      gperf \
      gnutls-bin \
      ipcalc \
      libcjose-dev \
      libcurl4-gnutls-dev \
      libev-dev \
      libgnutls28-dev \
      libhttp-parser-dev \
      libjansson-dev \
      libkrb5-dev \
      libllhttp-dev \
      liblz4-dev \
      libnl-route-3-dev \
      liboath-dev \
      libpam0g-dev \
      libprotobuf-c-dev \
      libradcli-dev \
      libreadline-dev \
      libseccomp-dev \
      libssl-dev \
      libtalloc-dev \
      libtasn1-bin \
      libtool \
      libuid-wrapper \
      libwrap0-dev \
      meson \
      nettle-dev \
      ninja-build \
      openconnect \
      pkg-config \
      protobuf-c-compiler \
      ruby-ronn \
      xz-utils \
      yajl-tools \
    && curl -fL "https://www.infradead.org/ocserv/download/ocserv-${OCSERV_VERSION}.tar.xz" \
      -o "/tmp/ocserv-${OCSERV_VERSION}.tar.xz" \
    && if [ -n "${OCSERV_SHA256}" ]; then \
         echo "${OCSERV_SHA256}  /tmp/ocserv-${OCSERV_VERSION}.tar.xz" | sha256sum -c -; \
       else \
         echo "WARNING: OCSERV_SHA256 is not set; ocserv tarball integrity not verified" >&2; \
         sha256sum "/tmp/ocserv-${OCSERV_VERSION}.tar.xz"; \
       fi \
    && tar -C /tmp -xf "/tmp/ocserv-${OCSERV_VERSION}.tar.xz" \
    && cd "/tmp/ocserv-${OCSERV_VERSION}" \
    && meson setup build -Doidc-auth=enabled \
    && ninja -C build install

FROM node:22-trixie-slim AS frontend-base
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json frontend/tsconfig.json frontend/vite.config.ts frontend/vitest.config.ts frontend/index.html ./
COPY frontend/public ./public
COPY frontend/src ./src
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund

FROM frontend-base AS frontend-test
RUN npm audit --audit-level=moderate && npm test && npm run build

FROM frontend-base AS frontend
RUN npm run build

FROM python:3.12-slim-trixie AS backend-test

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# gnutls-bin: the certificate tests that need a real certtool run here
# instead of being skipped.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gnutls-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kornode
COPY pyproject.toml README.md ./
COPY backend ./backend
COPY templates ./templates
COPY tests ./tests
COPY config.example.yaml ./config.example.yaml
COPY examples ./examples
RUN pip install --no-cache-dir '.[dev]' \
    && python -m ruff check backend tests \
    && python -m mypy backend \
    && python -m pytest \
    && korctl --config config.example.yaml config render --dry-run

FROM debian:${DEBIAN_VERSION}-slim AS runtime

ARG DEBIAN_VERSION
ARG DEBIAN_CODENAME
ARG OCSERV_VERSION

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    KORNODE_CONFIG=/etc/kornode/config.yaml \
    KORNODE_TEMPLATE_DIR=/usr/share/kornode/templates \
    DEBIAN_VERSION=${DEBIAN_VERSION} \
    DEBIAN_CODENAME=${DEBIAN_CODENAME} \
    OCSERV_VERSION=${OCSERV_VERSION} \
    PATH="/opt/kornode/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

RUN rm -f /etc/apt/apt.conf.d/docker-clean \
    && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' \
      > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=tmpfs,target=/var/log \
    --mount=type=tmpfs,target=/var/tmp \
    --mount=type=tmpfs,target=/tmp \
    apt-get update \
    && apt-get install -y --no-install-recommends \
      adduser \
      ca-certificates \
      bash \
      certbot \
      curl \
      dnsmasq \
      gnutls-bin \
      haproxy \
      inotify-tools \
      iproute2 \
      iputils-ping \
      jq \
      less \
      libcjose0 \
      libcurl4 \
      libev4t64 \
      libgnutls30t64 \
      libhttp-parser2.9 \
      libjansson4 \
      libllhttp9.2 \
      liblz4-1 \
      libmaxminddb0 \
      libnl-3-200 \
      libnl-route-3-200 \
      liboath0t64 \
      libpam-oath \
      libpam0g \
      libprotobuf-c1 \
      libradcli4 \
      libreadline8t64 \
      libseccomp2 \
      libtalloc2 \
      libtasn1-6 \
      libwrap0 \
      nftables \
      oathtool \
      openconnect \
      procps \
      python3 \
      python3-pip \
      python3-venv \
      qrencode \
      supervisor \
      util-linux \
      vpnc-scripts \
      xxd \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/log/*

COPY --from=ocserv-builder /usr/local /usr/local

WORKDIR /opt/kornode
COPY --from=frontend /app/frontend/dist /usr/share/kornode/frontend
COPY templates /usr/share/kornode/templates

RUN --mount=type=bind,source=.,target=/src,readonly \
    --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    python3 -m venv /opt/kornode/.venv \
    && pip install --upgrade pip \
    && mkdir -p /tmp/kornode-src \
    && cp -a /src/. /tmp/kornode-src/ \
    && pip install /tmp/kornode-src \
    && rm -rf /tmp/kornode-src \
    && ln -sfn /usr/local/sbin/ocserv /usr/sbin/ocserv \
    && ln -sfn /opt/kornode/.venv/bin/python3 /usr/local/bin/python \
    && ln -sfn /opt/kornode/.venv/bin/korctl /usr/local/bin/korctl \
    && ln -sfn /opt/kornode/.venv/bin/kornode /usr/local/bin/kornode \
    && ln -sfn /opt/kornode/.venv/bin/uvicorn /usr/local/bin/uvicorn \
    && ldconfig \
    && ocserv --version

VOLUME ["/etc/kornode", "/var/lib/kornode", "/var/log/kornode"]

EXPOSE 443/tcp 443/udp 8443/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -m kornode.healthcheck

ENTRYPOINT ["kornode"]
