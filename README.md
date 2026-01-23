# RAuth: High-Performance Auth Proxy & Management

[![Build and Push](https://github.com/arumes31/rauth/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/arumes31/rauth/actions/workflows/build.yml)
[![Go Security and Quality Scan](https://github.com/arumes31/rauth/actions/workflows/go-security.yml/badge.svg?branch=main)](https://github.com/arumes31/rauth/actions/workflows/go-security.yml)
[![Container Security Scan](https://github.com/arumes31/rauth/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/arumes31/rauth/actions/workflows/security.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/arumes31/rauth?label=Go&logo=go)](https://github.com/arumes31/rauth/blob/main/go.mod)
[![License](https://img.shields.io/github/license/arumes31/rauth?label=License&color=blue)](https://github.com/arumes31/rauth/blob/main/LICENSE)

RAuth is a lightweight, ultra-fast authentication proxy and user management system written in **Go**. It is designed to sit behind an Nginx `auth_request` module to provide secure access control, 2FA, and audit logging for your web applications.

## 🚀 Features

- **Blazing Fast**: Written in Go 1.24 for sub-millisecond authentication checks.
- **Modern UI**: Clean, responsive dashboard using Bootstrap 5, featuring human-readable audit logs and session monitoring.
- **Security First**:
  - **AES-256-GCM** Authenticated Encryption for tokens.
  - TOTP (2FA) support.
  - **Instant Expiry on Country Change**: Automatically invalidates sessions if a geo-location change is detected.
  - Built-in Atomic Rate Limiting.
  - CSRF protection on all forms.
  - Session tracking with global invalidation.
- **Smart Session Management**:
  - **2-Day Default Validity**: Configurable session lifetimes.
  - **IP-Based Refresh**: Automatically extends sessions when accessed from the same IP address.
  - Multiple concurrent sessions allowed across different devices.
- **Structured Logging**: Built-in observability using Go's `slog` for structured, machine-readable logs.
- **Group-Based Access (RBAC)**: Restrict services to specific user groups via Nginx headers.
- **Audit Logging**: Comprehensive activity tracking with formatted timestamps.
- **Self-Service**: Users can manage their own passwords and view their security activity.
- **Zero-Dependency Container**: Minimal footprint using multi-stage Docker builds.

## 🛠 Architecture

- **Backend**: Go 1.24 (Echo Framework)
- **Database**: Redis (Optimized with connection pooling and timeouts across 4 isolated databases).
- **External Integration**: Geo-IP service with in-memory caching for high-performance region-based security.
- **CI/CD**: Advanced GitHub Actions with Docker Layer Caching, Gosec, golangci-lint, and Trivy security scanning.

## 📦 Deployment

### 1. Prerequisites
- Docker & Docker Compose
- A MaxMind License Key (for the GeoIP service)

### 2. Quick Start
1. Clone the repository.
2. Create a `.env` file (see `example.env`).
3. Run the stack:
   ```bash
   docker-compose up -d
   ```

### 3. Nginx Integration
Configure your protected application to use RAuth for authentication. See `nginx-proxy-example.conf` for a full template.

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_SECRET` | Secret key for token encryption (min. 32 chars recommended) | (Required) |
| `TOKEN_VALIDITY_MINUTES` | How long a session remains valid | `2880` (2 days) |
| `INITIAL_USER` | Admin username created on startup | `admin` |
| `INITIAL_PASSWORD`| Admin password created on startup | (Required) |
| `COOKIE_DOMAIN` | Domain for the auth cookie | `reitetschlaeger.com` |
| `REDIS_HOST` | Redis server address | `rauth-auth-redis` |
| `REDIS_PASSWORD` | Optional Redis password | `""` |

## ✅ Production Checklist

- [ ] Change `INITIAL_PASSWORD` after first login.
- [ ] Set `SERVER_SECRET` to a unique, random string.
- [ ] Ensure `COOKIE_DOMAIN` matches your top-level domain.
- [ ] Use `HTTPS` only (the app sets `Secure`, `HttpOnly`, and `SameSite=Lax` cookies).

## 🧪 Development & Testing

Run unit tests:
```bash
go test ./...
```

The project uses GitHub Actions for CI/CD, including:
- Automated testing and linting.
- Docker image builds with layer caching.
- Security scanning (Gosec & Trivy).

---
Built with ❤️ for secure and fast self-hosting.