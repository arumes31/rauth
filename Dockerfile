# Build stage
FROM golang:1.25-alpine AS builder

# Add dependencies for build
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -v -o rauth main.go

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Copy geoipupdate binary from official image
COPY --from=ghcr.io/maxmind/geoipupdate:latest /usr/bin/geoipupdate /usr/bin/geoipupdate

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