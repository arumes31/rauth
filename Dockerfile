# Build stage
FROM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder

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
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Copy geoipupdate binary built from source in the builder stage
COPY --from=builder /usr/bin/geoipupdate /usr/bin/geoipupdate

WORKDIR /root/

COPY --from=builder /app/rauth .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Create directory for GeoIP database
RUN mkdir -p /app/geoip

EXPOSE 80

ENTRYPOINT ["./entrypoint.sh"]
