FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/auth ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/auth-http ./cmd/http && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/auth-probe ./cmd/probe

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/auth" \
      org.opencontainers.image.description="Placitum auth inspector: second factor gate and login form" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-auth" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/auth /out/auth-http /out/auth-probe /usr/local/bin/
RUN mkdir -p /app/profiles/profiles/default && \
    echo "mode: off" > /app/profiles/profiles/default/profile.yaml
COPY web ./web
COPY inspector.conf ./inspector.conf

RUN adduser -D -H -u 10001 auth && \
    mkdir -p /var/lib/waf/auth && \
    chown -R auth:auth /app /var/lib/waf
USER auth

ENV NATS_URL=nats://nats:4222 \
    WAF_AUTH_SUBJECT=waf.req.auth \
    WAF_AUTH_NAME=auth \
    WAF_AUTH_PROFILES=/app/profiles \
    WAF_AUTH_DATA=/var/lib/waf/auth \
    WAF_AUTH_WEB=/app/web \
    WAF_AUTH_LISTEN=:8080 \
    WAF_AUTH_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["auth-probe", "--quiet", "--timeout", "1s"]

CMD ["auth"]
