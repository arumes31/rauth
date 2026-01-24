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

RAuth is a lightweight, ultra-fast authentication proxy and user management system written in **Go**. It is designed to sit behind an Nginx `auth_request` module to provide secure access control, MFA (TOTP & Passkeys), and real-time observability for your self-hosted infrastructure.

## 🚀 Features

- **Blazing Fast**: Written in Go 1.25 for sub-millisecond authentication checks.
- **Passkey Support (WebAuthn)**: Modern, passwordless authentication using security keys or biometrics.
- **Consolidated Architecture**: Native Go Geo-IP lookups (no external services needed).
- **Observability**: Built-in `/metrics` endpoint for Prometheus monitoring.
- **Modern UI**: Clean "Hacker" red glassmorphism theme with human-readable audit logs.
- **Smart Session Management**:
  - **IP-Based Refresh**: Automatically extends sessions when accessed from the same IP.
  - **Geo-Fencing**: Instant session invalidation if a country change is detected.
  - **Metadata Tracking**: Monitor active sessions with User-Agent and Start Time.

## 🛡️ Security Architecture

- **AES-256-GCM Encryption**: High-standard authenticated encryption for session tokens.
- **Multi-Factor Auth**: Native support for both TOTP (Google Authenticator) and WebAuthn (Passkeys).
- **Atomic Rate Limiting**: Redis-backed protection against brute-force attacks.
- **CSRF & XSS Protection**: Hardened against common web vulnerabilities.
- **Metrics Security**: `/metrics` access restricted to private subnets and Tailscale by default.

## 🛠️ Technical Stack

- **Backend**: Go 1.25 (Echo Framework)
- **Database**: Redis 8.0 (Alpine)
- **Geo-IP**: Native MMDB integration (`geoip2-golang`)
- **Monitoring**: Prometheus Client
- **Frontend**: Bootstrap 5 + Matrix.js (Self-hosted assets)

## 📦 Deployment

### 1. Prerequisites
- Docker & Docker Compose
- MaxMind Account ID & License Key (for Geo-IP updates)

### 2. Quick Start
1. Clone the repository.
2. Setup environment:
   ```bash
   cp example.env .env
   # Edit .env with your secrets and MaxMind keys
   ```
3. Start the stack:
   ```bash
   docker-compose up -d
   ```

### 3. Nginx Integration
RAuth utilizes the Nginx `auth_request` module. Detailed configuration examples can be found in [nginx-proxy-example.conf](nginx-proxy-example.conf).

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_SECRET` | Secret key for encryption (min. 32 chars) | (Required) |
| `MAXMIND_ACCOUNT_ID` | Your MaxMind Account ID | (Required) |
| `MAXMIND_LICENSE_KEY` | Your MaxMind License Key | (Required) |
| `METRICS_ALLOWED_IPS` | Allowed IPs/CIDR for `/metrics` | (Private IPs + Tailscale) |
| `TOKEN_VALIDITY_MINUTES`| Session validity duration | `2880` (2 days) |
| `COOKIE_DOMAIN` | Primary domain for cookies | `example.com` |
| `ALLOWED_HOSTS` | Allowed redirect hosts | `localhost,127.0.0.1` |

## 📊 Monitoring
RAuth exposes standard Prometheus metrics at `/metrics`. 
- `rauth_login_success_total`: Successful logins.
- `rauth_active_sessions`: Gauge of current valid sessions in Redis.
- `rauth_rate_limit_hits_total`: Requests throttled by the rate limiter.

## 💻 Development

### Running Tests Locally
```bash
# Requires miniredis
go test -v ./...
```

### Local CI/CD Verification
```bash
act -j test -W .github/workflows/tests.yml
```

---
Built with ❤️ for secure and observable self-hosting.