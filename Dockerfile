# Build Stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy mod file
COPY go.mod ./

# Copy source code
COPY . .

# Tidy, download and build in one step to ensure go.sum is respected
RUN go mod tidy && \
    go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -v -o rauth main.go

# Final Stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/rauth .

# Expose port
EXPOSE 80

# Run the application
CMD ["./rauth"]