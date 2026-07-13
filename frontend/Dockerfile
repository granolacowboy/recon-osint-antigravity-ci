# syntax=docker/dockerfile:1.7
# Build with the repository root as context:
# docker build --file frontend/Dockerfile .

ARG NODE_IMAGE=node:24.14.1-alpine3.23@sha256:8510330d3eb72c804231a834b1a8ebb55cb3796c3e4431297a24d246b8add4d5
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.28.2-alpine@sha256:7377697a821c131a924a7105fafbe7414db4e9fcc77a6f08f776f33f141ec3f8

FROM ${NODE_IMAGE} AS build

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
ARG VITE_API_URL
ARG VITE_OIDC_AUTHORITY=
ARG VITE_OIDC_CLIENT_ID=
ARG VITE_OIDC_AUDIENCE=
ARG VITE_OIDC_SCOPE="openid profile email"
ARG VITE_OIDC_REDIRECT_URI=
ARG VITE_OIDC_POST_LOGOUT_URI=
ENV VITE_API_URL=${VITE_API_URL} \
    VITE_OIDC_AUTHORITY=${VITE_OIDC_AUTHORITY} \
    VITE_OIDC_CLIENT_ID=${VITE_OIDC_CLIENT_ID} \
    VITE_OIDC_AUDIENCE=${VITE_OIDC_AUDIENCE} \
    VITE_OIDC_SCOPE=${VITE_OIDC_SCOPE} \
    VITE_OIDC_REDIRECT_URI=${VITE_OIDC_REDIRECT_URI} \
    VITE_OIDC_POST_LOGOUT_URI=${VITE_OIDC_POST_LOGOUT_URI}
RUN test -n "${VITE_API_URL}" \
    || (echo "VITE_API_URL build argument is required" >&2; exit 1)
RUN node -e "const fs=require('node:fs'); const origin=new URL(process.env.VITE_API_URL).origin; const template=fs.readFileSync('nginx.conf','utf8'); if(!template.includes('__API_ORIGIN__')) throw new Error('nginx CSP API placeholder is missing'); fs.writeFileSync('default.conf', template.replaceAll('__API_ORIGIN__', origin));"
RUN npm run build


FROM ${NGINX_IMAGE} AS runtime

USER 0:0
# The pinned upstream image still contains fixable Alpine and Nginx CVEs.
# Remove unused ABI-bound dynamic modules, then install exact fixed revisions.
RUN apk del \
        curl \
        libcurl \
        nginx-module-geoip \
        nginx-module-image-filter \
        nginx-module-njs \
        nginx-module-xslt \
    && apk add --no-cache --upgrade \
        libcrypto3=3.5.7-r0 \
        libssl3=3.5.7-r0 \
        musl=1.2.5-r23 \
        musl-utils=1.2.5-r23 \
        nghttp2-libs=1.69.0-r0 \
        nginx=1.28.3-r4

COPY --from=build --chown=101:101 /build/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /build/dist /usr/share/nginx/html

USER 101:101
EXPOSE 8080
STOPSIGNAL SIGQUIT

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "--quiet", "--output-document=-", "http://127.0.0.1:8080/healthz"]
