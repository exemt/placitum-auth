# Контекст сборки -- корень инспектора (inspectors/auth).
#
#     docker build -f deploy/Dockerfile -t placitum/auth .
#     docker buildx build -f deploy/Dockerfile -t placitum/auth \
#         "https://github.com/exemt/placitum-auth.git#develop"
#
# Один образ, два контейнера: inspector-auth запускает `auth`, auth-http --
# `auth-http`. Ключ подписи у них общий, и это единственное, чем они связаны.

FROM golang:1.25-alpine AS build

WORKDIR /src

# Прокси модулей -- аргументом: в изолированном контуре подставляют своё зеркало.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0

# Тесты в сборке: образ с красными тестами ставить нельзя. Сверка словаря
# действий со схемой провода здесь пропускается сама -- схема живёт в
# платформе, а не в контексте сборки.
RUN go test ./...

# Сборка в бинарь: версия и ревизия видны в журнале старта и в кадре
# присутствия, а не только в метках образа.
ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/auth ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/auth-http ./cmd/http && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/auth-probe ./cmd/probe

FROM alpine:3.22

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает.
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
# Профили оператора в образ не едут: их доставляет контроллер поколением.
# Загрузчик без профиля default не поднимается, поэтому образ стартует с
# одним выключенным -- подсистема объявлена и молчит до первого поколения.
RUN mkdir -p /app/profiles/profiles/default && \
    echo "mode: off" > /app/profiles/profiles/default/profile.yaml
COPY web ./web
COPY inspector.conf ./inspector.conf

# Каталог применённого поколения создаётся заранее и отдаётся процессу: том
# монтируется поверх него и наследует владельца, иначе первая же раскатка
# упирается в permission denied и остаётся на bootstrap-профилях.
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

# Проба идёт тем же путём, что модуль: публикует инспекцию и ждёт вердикт.
# Ожидаемого вердикта нет нарочно -- он зависит от режима профиля, а живость
# доказывает сам факт ответа. Для auth-http это переопределяется в compose.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["auth-probe", "--quiet", "--timeout", "1s"]

CMD ["auth"]
