FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/mcp-audit ./cmd/mcp-audit

FROM alpine:3.20
LABEL org.opencontainers.image.title="mcp-audit" \
      org.opencontainers.image.description="Security and observability proxy for MCP servers" \
      org.opencontainers.image.source="https://github.com/P4ST4S/mcp-audit" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN addgroup -S mcpaudit && \
    adduser -S -G mcpaudit -H -h /nonexistent -s /sbin/nologin mcpaudit && \
    apk add --no-cache ca-certificates && \
    mkdir -p /data && \
    chown mcpaudit:mcpaudit /data

WORKDIR /data
COPY --from=builder /out/mcp-audit /usr/local/bin/mcp-audit
USER mcpaudit
ENTRYPOINT ["mcp-audit"]
