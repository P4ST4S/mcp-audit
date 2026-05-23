FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mcp-audit ./cmd/mcp-audit

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/mcp-audit .
ENTRYPOINT ["./mcp-audit"]
