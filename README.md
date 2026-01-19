# RAuth: High-Performance Auth Proxy & Management

RAuth is a lightweight, ultra-fast authentication proxy and user management system written in **Go**. It is designed to sit behind an Nginx `auth_request` module to provide secure access control, 2FA, and audit logging for your web applications.

## 🚀 Features

- **Blazing Fast**: Rewritten in Go for sub-millisecond authentication checks.
- **Modern UI**: Clean, responsive dashboard using Bootstrap 5 and local assets.
- **Security First**:
  - AES-256-CBC token encryption.
  - TOTP (2FA) support.
  - Built-in Rate Limiting.
  - CSRF protection on all forms.
  - Session tracking and global invalidation.
- **Group-Based Access (RBAC)**: Restrict services to specific user groups via Nginx headers.
- **Audit Logging**: Comprehensive activity tracking stored in Redis.
- **Self-Service**: Users can manage their own passwords and view their security activity.
- **Zero-Dependency Container**: No PHP or Nginx needed inside the app container.

## 🛠 Architecture

- **Backend**: Go (Echo Framework)
- **Database**: Redis (User data, Sessions, Rate limits, Audit logs)
- **External Integration**: MaxMind GeoIP for region-based security.

## 📦 Deployment

### 1. Prerequisites
- Docker & Docker Compose
- A MaxMind License Key (for GeoIP)

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
| `SERVER_SECRET` | 32-char key for token encryption | (Required) |
| `INITIAL_USER` | Admin username created on startup | `admin` |
| `INITIAL_PASSWORD`| Admin password created on startup | (Required) |
| `COOKIE_DOMAIN` | Domain for the auth cookie | `reitetschlaeger.com` |
| `REDIS_HOST` | Redis server address | `rauth-auth-redis` |

## 🧪 Development & Testing

Run unit tests:
```bash
go test ./internal/core/...
```

Build the Docker image locally:
```bash
docker build -t rauth-auth .
```

---
Built with ❤️ for secure and fast self-hosting.
