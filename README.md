# RAuth: High-Performance Auth Proxy & Management

<p align="center">
  <img src="https://img.shields.io/github/go-mod/go-version/arumes31/rauth?label=Go&logo=go&color=00ADD8" alt="Go Version">
  <img src="https://img.shields.io/github/license/arumes31/rauth?label=License&color=blue" alt="License">
  <img src="https://img.shields.io/github/last-commit/arumes31/rauth/test?color=green" alt="Last Commit">
</p>

<p align="center">
  <a href="https://github.com/arumes31/rauth/actions/workflows/build.yml">
    <img src="https://github.com/arumes31/rauth/actions/workflows/build.yml/badge.svg?branch=test" alt="Build Status">
  </a>
  <a href="https://github.com/arumes31/rauth/actions/workflows/go-security.yml">
    <img src="https://github.com/arumes31/rauth/actions/workflows/go-security.yml/badge.svg?branch=test" alt="Security Scan">
  </a>
  <a href="https://github.com/arumes31/rauth/actions/workflows/security.yml">
    <img src="https://github.com/arumes31/rauth/actions/workflows/security.yml/badge.svg?branch=test" alt="Container Scan">
  </a>
</p>

---

RAuth is a lightweight, ultra-fast authentication proxy and user management system written in **Go**. It is designed to sit behind an Nginx `auth_request` module to provide secure access control, 2FA, and audit logging for your web applications.

## 📖 Table of Contents
- [🚀 Features](#-features)
- [🛡️ Security Architecture](#️-security-architecture)
- [🛠️ Technical Stack](#️-technical-stack)
- [📦 Deployment](#-deployment)
- [⚙️ Environment Variables](#️-environment-variables)
- [💻 Development](#-development)
- [✅ Production Checklist](#-production-checklist)

## 🚀 Features

- **Blazing Fast**: Written in Go 1.24 for sub-millisecond authentication checks.
- **Modern UI**: Clean, responsive dashboard using Bootstrap 5, featuring human-readable audit logs and session monitoring.
- **Smart Session Management**:
  - **2-Day Default Validity**: Configurable session lifetimes.
  - **IP-Based Refresh**: Automatically extends sessions when accessed from the same IP address.
  - **Multi-Device Support**: Concurrent sessions allowed across different devices.
- **Structured Logging**: Built-in observability using Go's `slog` for structured, machine-readable logs.
- **Zero-Dependency Container**: Minimal footprint using multi-stage Docker builds.

## 🛡️ Security Architecture

- **AES-256-GCM Encryption**: High-standard authenticated encryption for tokens, ensuring both confidentiality and integrity.
- **Instant Expiry on Country Change**: Automatically invalidates sessions if a geo-location change is detected between requests.
- **TOTP (2FA)**: Native support for Time-based One-Time Passwords.
- **Atomic Rate Limiting**: Redis-backed rate limiting to prevent brute-force attacks.
- **CSRF Protection**: Robust protection on all state-changing forms.
- **Geo-IP Caching**: High-performance in-memory cache for IP-to-country lookups.

## 🛠️ Technical Stack

- **Backend**: Go 1.24 (Echo Framework)
- **Database**: Redis (Optimized with connection pooling and timeouts).
- **Frontend**: Bootstrap 5 + Vanilla JS.
- **CI/CD**: GitHub Actions with Docker Layer Caching, Gosec, golangci-lint, and Trivy.

## 📦 Deployment

### 1. Prerequisites
- Docker & Docker Compose
- A MaxMind License Key (for the GeoIP service)

### 2. Quick Start
1. Clone the repository.
2. Create a `.env` file from the sanitized example:
   ```bash
   cp example.env .env
   ```
3. Run the stack:
   ```bash
   docker-compose up -d
   ```

### 3. Using Pre-built GHCR Images
Instead of building locally, you can use the pre-built images from the GitHub Container Registry. Create a `docker-compose.ghcr.yml` or update your existing one:

```yaml
services:
  rauth-auth-service:
    image: ghcr.io/arumes31/rauth-auth:latest
    container_name: rauth-auth-service
    ports:
      - "5980:80"
    environment:
      - REDIS_HOST=rauth-auth-redis
      - SERVER_SECRET=${SERVER_SECRET}
      # ... other environment variables
    depends_on:
      - rauth-auth-redis

  rauth-geo-service:
    image: ghcr.io/arumes31/rauth-geo:latest
    container_name: rauth-geo-service
    environment:
      - MAXMIND_LICENSE_KEY=${MAXMIND_LICENSE_KEY}
      # ... other environment variables
```

Run with:
```bash
docker-compose -f docker-compose.ghcr.yml up -d
```

### 4. Nginx Integration
RAuth utilizes the Nginx `auth_request` module to provide a centralized authentication layer. When a user accesses a protected service, Nginx intercepts the request and performs an internal subrequest to RAuth's validation endpoint. RAuth verifies the session token, enforces security policies (like geo-fencing), and validates the user's status. Based on the response, Nginx either permits access—propagating user identity headers to your backend—or triggers a redirect to the RAuth login portal.

**Key configuration steps:**
1.  Define a `/rauth-verify` location that proxies to RAuth's `/rauthvalidate`.
2.  Use `auth_request /rauth-verify;` in your application's `location` block.
3.  Handle `401` errors by redirecting to the RAuth login page.

Detailed configuration examples can be found in [nginx-proxy-example.conf](nginx-proxy-example.conf).

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_SECRET` | Secret key for token encryption (min. 32 chars) | (Required) |
| `TOKEN_VALIDITY_MINUTES` | Session validity duration | `2880` (2 days) |
| `INITIAL_USER` | Admin username | `admin` |
| `INITIAL_PASSWORD`| Admin password | (Required) |
| `INITIAL_EMAIL` | Admin email | `admin@local` |
| `INITIAL_2FA_SECRET` | Admin 2FA secret (optional) | (None) |
| `COOKIE_DOMAIN` | Comma-separated domains for auth cookies. First is primary. | `example.com` |
| `ALLOWED_HOSTS` | Additional allowed redirect hosts (subdomains of `COOKIE_DOMAIN` are auto-allowed) | `localhost,127.0.0.1` |
| `PWD_MIN_LENGTH` | Minimum password length | `8` |
| `PWD_REQUIRE_UPPER` | Require uppercase | `true` |
| `PWD_REQUIRE_LOWER` | Require lowercase | `true` |
| `PWD_REQUIRE_NUMBER` | Require number | `true` |
| `PWD_REQUIRE_SPECIAL` | Require special char | `true` |

## 💻 Development

### Running Tests Locally
```bash
go test -v ./...
```

### Local CI/CD Testing
You can run GitHub Actions locally using [act](https://github.com/nektos/act):
```bash
act -j test -W .github/workflows/build.yml
```

### Docker Build
```bash
docker-compose build --no-cache
```

## ✅ Production Checklist

- [x] Use `HTTPS` only (secure cookies enabled).
- [ ] Set a unique `SERVER_SECRET` (at least 32 characters).
- [ ] Configure `ALLOWED_HOSTS` for strict redirection.
- [ ] Update `INITIAL_PASSWORD` immediately after first login at `/rauthlogin`.

---
Built with ❤️ for secure and fast self-hosting.
