# syntax=docker/dockerfile:1

# Build on the native platform and cross-compile for the target platform.
FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    goarm=""; \
    if [ "${TARGETARCH}" = "arm" ]; then goarm="${TARGETVARIANT#v}"; fi; \
    module="github.com/hightemp/http_ssh_proxy/internal/buildinfo"; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" GOARM="${goarm}" \
    go build -trimpath \
      -ldflags "-s -w -X ${module}.Version=${VERSION} -X ${module}.Commit=${COMMIT} -X ${module}.BuildTime=${BUILD_TIME}" \
      -o /out/http_ssh_proxy ./cmd/http_ssh_proxy

# Distroless static: no shell or package manager, CA certificates included for
# HTTPS upstream verification, and a non-root user by default.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="http_ssh_proxy" \
      org.opencontainers.image.description="HTTP forward proxy that tunnels requests and CONNECT through one managed SSH connection" \
      org.opencontainers.image.source="https://github.com/hightemp/http_ssh_proxy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

COPY --from=build /out/http_ssh_proxy /usr/local/bin/http_ssh_proxy

USER nonroot:nonroot
EXPOSE 8888
ENTRYPOINT ["/usr/local/bin/http_ssh_proxy"]
CMD ["-config", "/etc/http_ssh_proxy/config.yaml"]
