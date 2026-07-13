# Build stage
FROM golang:1.26.5-alpine AS builder

# Add dependencies for build
RUN apk add --no-cache ca-certificates tzdata git

# Build geoipupdate from source with the current Go toolchain and patched
# dependencies (upstream's prebuilt image ships a stale Go 1.24.5 stdlib:
# CVE-2026-42504, CVE-2026-27145, CVE-2026-42507, CVE-2026-39824)
RUN git clone --depth 1 --branch v7.1.1 https://github.com/maxmind/geoipupdate /tmp/geoipupdate \
    && cd /tmp/geoipupdate \
    && go get golang.org/x/sys@latest \
    && go mod tidy \
    && CGO_ENABLED=0 GOOS=linux go build -o /usr/bin/geoipupdate ./cmd/geoipupdate

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -v -o rauth main.go

# Runtime stage
FROM alpine:latest

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