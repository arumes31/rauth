# RAuth: High-Performance Auth Proxy & Identity Management

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
</p>

---

RAuth is a lightweight, high-performance authentication proxy and user management system written in **Go**. It is specifically architected to provide a centralized, secure access control layer for self-hosted infrastructure via the Nginx `auth_request` module.

RAuth eliminates the complexity of full-scale identity providers while maintaining enterprise-grade security standards like **Passkey (WebAuthn)** support, **AES-256-GCM** session encryption, and real-time **Prometheus** observability.

## 📖 Table of Contents
- [🚀 Core Features](#-core-features)
- [🛡️ Security Architecture](#-security-architecture)
- [📦 Technical Stack](#-technical-stack)
- [🔧 Nginx Integration](#-nginx-integration)
- [📊 Monitoring & Observability](#-monitoring--observability)
- [⚙️ Configuration](#-configuration)
- [🚀 Deployment](#-deployment)
- [💻 Development](#-development)

---

## 🚀 Core Features

### 🔐 Multi-Factor Authentication (MFA)
*   **WebAuthn / Passkeys**: Modern, phishing-resistant authentication using hardware keys (YubiKey), TouchID, FaceID, or Windows Hello.
*   **TOTP Support**: Compatible with Google Authenticator, Authy, and Bitwarden.
*   **Enforced Setup**: New users are automatically guided through a secure MFA enrollment process.

### 🌐 Smart Session Management
*   **Sub-millisecond Validation**: Optimized Go backend with Redis caching for near-zero latency.
*   **Geo-Fencing**: Built-in MaxMind integration. If a session is accessed from a new country, it is instantly invalidated to prevent session hijacking.
*   **Device Awareness**: Logs and displays active sessions with User-Agent and IP metadata.
*   **IP-Based Refresh**: Automatically extends session validity as long as the user remains on the same IP.

### 🛠️ Administrative Control
*   **User Management**: Create, delete, and manage users via a secure dashboard.
*   **Credential Resets**: Force password changes or reset 2FA seeds for users.
*   **Audit Logging**: Every sensitive action (logins, failures, admin changes) is captured in a structured, searchable audit feed.

---

## 🛡️ Security Architecture

RAuth is built with a "Security-First" mindset:

1.  **Authenticated Encryption**: All session tokens stored in cookies are encrypted using **AES-256-GCM**. This provides both confidentiality and tamper-proof integrity.
2.  **Brute-Force Protection**: Atomic Redis-backed rate limiting per IP and per username.
3.  **Cross-Site Scripting (XSS)**: Strict Content Security Policy (CSP) and input sanitization.
4.  **CSRF Protection**: All state-changing operations require a cryptographically secure synchronized token.
5.  **Secure Cookies**: Cookies are strictly `HttpOnly`, `Secure`, and use `SameSite=Lax` to prevent client-side script access and CSRF.
6.  **Minimal Attack Surface**: The runtime environment is a hardened Alpine container with no shell access and minimal binaries.

---

## 📦 Technical Stack

*   **Runtime**: [Go 1.25+](https://golang.org/) (High-concurrency, memory-safe)
*   **Web Framework**: [Echo v4](https://echo.labstack.com/)
*   **Identity Store**: [Redis 8.0+](https://redis.io/)
*   **MFA Core**: [go-webauthn](https://github.com/go-webauthn/webauthn) & [pquerna/otp](https://github.com/pquerna/otp)
*   **Geo-IP**: Native Go MMDB integration via [geoip2-golang](https://github.com/oschwald/geoip2-golang)
*   **Monitoring**: [Prometheus Client](https://github.com/prometheus/client_golang)
*   **Frontend**: Native Bootstrap 5 with a custom Glassmorphism "Matrix" theme.

---

## 🔧 Nginx Integration

RAuth acts as an "Authorizer" for Nginx. When a request hits your proxy, Nginx performs a lightweight subrequest to RAuth to verify the user's session.

### Example Nginx Snippet

```nginx
# 1. Define the RAuth validation endpoint
location = /rauth-verify {
    internal;
    proxy_pass http://rauth-auth-service/rauthvalidate;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Real-IP $remote_addr;
}

# 2. Protect your application
location / {
    auth_request /rauth-verify;
    
    # Propagate user identity to your backend
    auth_request_set $user $upstream_http_x_rauth_user;
    proxy_set_header X-User $user;

    # Handle unauthorized users
    error_page 401 = @error401;
    
    proxy_pass http://your-app-backend;
}

location @error401 {
    return 302 https://auth.yourdomain.com/rauthlogin?rd=$scheme://$http_host$request_uri;
}
```

---

## 📊 Monitoring & Observability

RAuth exposes real-time metrics in Prometheus format at `/metrics`. 

### Security & Usage Metrics
*   `rauth_login_success_total`: Cumulative count of successful logins.
*   `rauth_login_failed_total`: Cumulative count of failed attempts (useful for alerting on brute-force).
*   `rauth_active_sessions`: Gauge showing the current number of valid sessions in Redis.
*   `rauth_rate_limit_hits_total`: Count of requests blocked by the internal throttler.
*   `rauth_audit_logs_total`: Counter categorized by action (e.g., `USER_CHANGE_PASSWORD`, `ADMIN_DELETE_USER`).

### Access Control
By default, the `/metrics` endpoint is restricted to:
*   Localhost (`127.0.0.1`)
*   Private Subnets (`10.0.0.0/8`, etc.)
*   Tailscale IP ranges (`100.64.0.0/10`)

---

## ⚙️ Configuration

RAuth is configured via Environment Variables.

| Category | Variable | Description | Default |
|:---|:---|:---|:---|
| **Secret** | `SERVER_SECRET` | 32+ char key for AES encryption | **REQUIRED** |
| **MaxMind**| `MAXMIND_ACCOUNT_ID` | Your Account ID for Geo-IP updates | **REQUIRED** |
| **MaxMind**| `MAXMIND_LICENSE_KEY` | Your License Key for Geo-IP updates | **REQUIRED** |
| **Redis**  | `REDIS_HOST` | Hostname of the Redis instance | `rauth-auth-redis` |
| **Redis**  | `REDIS_PASSWORD` | Password for Redis auth | (None) |
| **Auth**   | `COOKIE_DOMAIN` | Domain for the auth cookie | `example.com` |
| **Auth**   | `TOKEN_VALIDITY` | Session duration in minutes | `2880` (2 days) |
| **Security**| `METRICS_ALLOWED_IPS`| CIDR list for `/metrics` access | (Private + Tailscale) |
| **Policy** | `PWD_MIN_LENGTH` | Minimum required password length | `8` |

---

## 🚀 Deployment

### Quick Start with Docker Compose

1.  **Clone & Prepare**:
    ```bash
    git clone https://github.com/arumes31/rauth.git
    cd rauth
    cp example.env .env
    ```
2.  **Configure**: Edit `.env` and provide your `SERVER_SECRET` and MaxMind credentials.
3.  **Launch**:
    ```bash
    docker-compose up -d
    ```

RAuth will automatically initialize the primary admin user defined in your environment variables. Access the dashboard at `http://localhost:5980/rauthmgmt`.

---

## 💻 Development

### Prerequisites
*   Go 1.25+
*   Redis (or [miniredis](https://github.com/alicebob/miniredis) for testing)

### Testing
We use a combination of unit tests, integration tests, and fuzzing to ensure core security logic remains robust.
```bash
go test -v ./...
```

### Local CI/CD
You can verify the entire pipeline (Linting, Security, Tests) locally using [act](https://github.com/nektos/act):
```bash
act -j test -W .github/workflows/tests.yml
```

---
Built with ❤️ for secure, fast, and private self-hosting.
