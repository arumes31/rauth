# Build stage
FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

# Add dependencies for build
RUN apk add --no-cache ca-certificates tzdata git

# Build geoipupdate from source with the current Go toolchain and patched
# dependencies (upstream's prebuilt image ships a stale Go 1.24.5 stdlib:
# CVE-2026-42504, CVE-2026-27145, CVE-2026-42507, CVE-2026-39824)
RUN git clone --depth 1 --branch v7.1.1 https://github.com/maxmind/geoipupdate /tmp/geoipupdate \
    && test "$(git -C /tmp/geoipupdate rev-parse HEAD)" = "6664d8b979d8ee43be2cfd2f92b8bdeed93c0ad7" \
    && cd /tmp/geoipupdate \
    && go get golang.org/x/net@v0.58.0 golang.org/x/sys@v0.47.0 \
    && go mod tidy \
    && CGO_ENABLED=0 GOOS=linux go build -o /usr/bin/geoipupdate ./cmd/geoipupdate

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -v -o rauth main.go

# Runtime stage
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Install runtime dependencies
RUN apk --no-cache upgrade \
    && apk --no-cache add ca-certificates tzdata \
    && addgroup -S -g 10001 rauth \
    && adduser -S -D -H -u 10001 -G rauth rauth

# Copy geoipupdate binary built from source in the builder stage
COPY --from=builder /usr/bin/geoipupdate /usr/bin/geoipupdate

WORKDIR /app

COPY --from=builder --chown=10001:10001 /app/rauth ./rauth
COPY --from=builder --chown=10001:10001 /app/templates ./templates
COPY --from=builder --chown=10001:10001 /app/static ./static
COPY --chown=10001:10001 entrypoint.sh ./entrypoint.sh
RUN chmod 0555 entrypoint.sh

# Create directory for GeoIP database
RUN install -d -o 10001 -g 10001 -m 0750 /app/geoip

ENV LISTEN_ADDR=:8080

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
