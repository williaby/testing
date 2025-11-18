# Cloudflare Tunnel Auth - Python Package

A secure, production-ready authentication library for FastAPI applications behind Cloudflare Tunnel.

## Features

- ✅ JWT token validation using Cloudflare Access
- ✅ Email whitelist with domain support
- ✅ User tier system (admin/full/limited)
- ✅ Session management (in-memory and Redis)
- ✅ Rate limiting
- ✅ CSRF protection
- ✅ Security headers
- ✅ Comprehensive security testing
- ✅ Production-ready with security hardening

## Installation

### From PyPI (once published)

```bash
pip install cloudflare-tunnel-auth
```

### From GitHub

```bash
pip install git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git
```

### From Local Source

```bash
git clone https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git
cd cloudflare-tunnel-auth
pip install -e .  # Editable install for development
```

## Quick Start

### Basic Setup

```python
from fastapi import FastAPI
from cloudflare_tunnel_auth import setup_cloudflare_auth

app = FastAPI()

# Minimal setup - uses environment variables
setup_cloudflare_auth(app)

@app.get("/protected")
async def protected_route(request: Request):
    user = request.state.user  # CloudflareUser object
    return {"email": user.email}
```

### Environment Variables

```bash
# Required
CLOUDFLARE_TEAM_DOMAIN=your-team.cloudflareaccess.com
CLOUDFLARE_AUDIENCE_TAG=your-audience-tag
CLOUDFLARE_ENABLED=true

# Optional
REQUIRE_CLOUDFLARE_HEADERS=true
ALLOWED_TUNNEL_IPS=127.0.0.1,::1
```

### Advanced Setup with Whitelist

```python
from fastapi import FastAPI, Depends
from cloudflare_tunnel_auth import (
    setup_cloudflare_auth_enhanced,
    CloudflareUser,
    get_current_user,
    require_admin,
)

app = FastAPI()

# Advanced setup with whitelist and tiers
setup_cloudflare_auth_enhanced(
    app,
    whitelist=["user@example.com", "@company.com"],
    admin_emails=["admin@company.com"],
    full_users=["@company.com"],
    limited_users=["contractor@external.com"],
    enable_sessions=True,
    session_timeout=3600,
)

@app.get("/user")
async def user_route(user: CloudflareUser = Depends(get_current_user)):
    return {"email": user.email, "tier": user.user_tier.value}

@app.get("/admin")
async def admin_route(user: CloudflareUser = Depends(require_admin)):
    return {"message": "Admin access granted"}
```

### With Redis Sessions (Production)

```python
from cloudflare_tunnel_auth import (
    setup_cloudflare_auth_enhanced,
    RedisSessionManager,
)

# Production-ready session management
session_manager = RedisSessionManager(
    redis_url="redis://localhost:6379/0",
    session_timeout=3600,
)

setup_cloudflare_auth_enhanced(
    app,
    whitelist=["@company.com"],
    admin_emails=["admin@company.com"],
    enable_sessions=True,
)
```

## Usage in Your Projects

### Project Structure

```
your-project/
├── requirements.txt          # Add cloudflare-tunnel-auth
├── .env                     # Configure settings
├── main.py                  # Your application
└── tests/
    └── test_app.py
```

### requirements.txt

```txt
fastapi>=0.104.0
uvicorn>=0.24.0
cloudflare-tunnel-auth>=1.0.0  # This package
```

### main.py

```python
from fastapi import FastAPI, Depends
from cloudflare_tunnel_auth import (
    setup_cloudflare_auth_enhanced,
    CloudflareUser,
    get_current_user,
)

app = FastAPI()

# Configure authentication
setup_cloudflare_auth_enhanced(
    app,
    whitelist=["@mycompany.com"],
    admin_emails=["admin@mycompany.com"],
    enable_sessions=True,
)

# Your routes
@app.get("/api/data")
async def get_data(user: CloudflareUser = Depends(get_current_user)):
    return {
        "data": "secret information",
        "user": user.email,
        "tier": user.user_tier.value,
    }
```

## Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git
cd cloudflare-tunnel-auth

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with all dependencies
pip install -e ".[dev,test,redis]"

# Run tests
pytest

# Run security tests
pytest tests/test_security_vulnerabilities.py -v

# Run linting
bandit -r src/
black src/ tests/
ruff check src/
```

### Running Tests

```bash
# All tests
pytest

# Security tests only
pytest tests/test_security_vulnerabilities.py

# With coverage
pytest --cov=cloudflare_tunnel_auth --cov-report=html

# Specific test
pytest tests/test_middleware.py::test_authentication
```

## Security

### Security Testing

This package includes comprehensive security testing:

```bash
# Run security vulnerability regression tests
pytest tests/test_security_vulnerabilities.py -v

# Run security scanning
bandit -r src/
safety check
```

### Security Features

- ✅ **Email Header Validation**: Prevents authentication bypass
- ✅ **JWT Token Validation**: Cryptographically secure token verification
- ✅ **Cloudflare Origin Validation**: Ensures requests came through tunnel
- ✅ **Rate Limiting**: Prevents brute force attacks
- ✅ **Production Protection**: Prevents accidental auth bypass
- ✅ **Session Security**: Cryptographically secure session IDs
- ✅ **CSRF Protection**: Double-submit cookie pattern
- ✅ **Timing Attack Protection**: Constant-time email comparison

See [SECURITY.md](SECURITY.md) for security policy and [CLOUDFLARE_TUNNEL_SECURITY_REVIEW.md](CLOUDFLARE_TUNNEL_SECURITY_REVIEW.md) for detailed security analysis.

## API Reference

### Main Functions

#### `setup_cloudflare_auth(app, **kwargs)`

Basic authentication setup.

**Parameters:**
- `app`: FastAPI application
- `excluded_paths`: List of paths to exclude (default: health/docs endpoints)
- `require_auth`: Whether authentication is required (default: True)
- `settings`: Optional CloudflareSettings instance

#### `setup_cloudflare_auth_enhanced(app, **kwargs)`

Advanced setup with whitelist and tiers.

**Parameters:**
- `app`: FastAPI application
- `whitelist`: List of allowed emails/domains
- `admin_emails`: List of admin emails
- `full_users`: List of full-tier users
- `limited_users`: List of limited-tier users
- `enable_sessions`: Enable session management (default: True)
- `session_timeout`: Session timeout in seconds (default: 3600)

### Dependencies

#### `get_current_user(request: Request) -> CloudflareUser`

Get authenticated user (raises 401 if not authenticated).

#### `get_current_user_optional(request: Request) -> CloudflareUser | None`

Get authenticated user or None.

#### `require_admin(request: Request) -> CloudflareUser`

Require admin privileges (raises 403 if not admin).

#### `require_tier(minimum_tier: UserTier) -> Callable`

Create dependency requiring minimum user tier.

### Models

#### `CloudflareUser`

Authenticated user model.

**Attributes:**
- `email`: User's email address
- `user_id`: Unique identifier
- `user_tier`: User tier (admin/full/limited)
- `is_admin`: Whether user is admin
- `can_access_premium_models`: Whether user can access premium features
- `session_id`: Session identifier (if sessions enabled)
- `claims`: Full JWT claims

#### `UserTier` (Enum)

User access tiers.

**Values:**
- `UserTier.ADMIN`: Full access + admin privileges
- `UserTier.FULL`: Full access to all features
- `UserTier.LIMITED`: Limited access

## Configuration

### Environment Variables

```bash
# Required
CLOUDFLARE_TEAM_DOMAIN=your-team.cloudflareaccess.com
CLOUDFLARE_AUDIENCE_TAG=abc123...

# Optional Security Settings
CLOUDFLARE_ENABLED=true
REQUIRE_CLOUDFLARE_HEADERS=true
ALLOWED_TUNNEL_IPS=127.0.0.1,::1
REQUIRE_EMAIL_VERIFICATION=true
LOG_AUTH_FAILURES=true

# Session Settings
ENABLE_SESSIONS=true
SESSION_TIMEOUT=3600

# Cookie Settings
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
COOKIE_PATH=/
COOKIE_DOMAIN=.example.com  # Optional

# Rate Limiting
RATE_LIMIT_ATTEMPTS=5
RATE_LIMIT_WINDOW=60
```

### Settings Class

```python
from cloudflare_tunnel_auth import CloudflareSettings

settings = CloudflareSettings(
    cloudflare_team_domain="your-team.cloudflareaccess.com",
    cloudflare_audience_tag="your-audience-tag",
    cloudflare_enabled=True,
    require_cloudflare_headers=True,
)
```

## Examples

See the [examples/](examples/) directory for complete examples:

- `basic_usage.py`: Minimal setup
- `advanced_usage.py`: Whitelist and tiers
- `secure_example.py`: Production configuration
- `complete_example.py`: All features

## Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  cloudflared:
    image: cloudflare/cloudflared:latest
    command: tunnel --no-autoupdate run --token ${TUNNEL_TOKEN}
    networks:
      - tunnel-network

  app:
    build: .
    environment:
      - CLOUDFLARE_TEAM_DOMAIN=${CLOUDFLARE_TEAM_DOMAIN}
      - CLOUDFLARE_AUDIENCE_TAG=${CLOUDFLARE_AUDIENCE_TAG}
      - CLOUDFLARE_ENABLED=true
      - REQUIRE_CLOUDFLARE_HEADERS=true
    networks:
      - tunnel-network
    expose:
      - "8000"

networks:
  tunnel-network:
    driver: bridge
```

## Versioning

This package follows [Semantic Versioning](https://semver.org/):

- **Major**: Breaking changes
- **Minor**: New features (backward compatible)
- **Patch**: Bug fixes

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

### Security Issues

**Do not open public issues for security vulnerabilities.**

Please report security issues to: security@yourcompany.com

See [SECURITY.md](SECURITY.md) for our security policy.

## License

MIT License - see [LICENSE](LICENSE) file.

## Support

- **Documentation**: [Full docs](https://your-docs-site.com)
- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth/issues)
- **Discussions**: [GitHub Discussions](https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth/discussions)

## Credits

Developed and maintained by [Your Name/Organization].

Built on:
- [FastAPI](https://fastapi.tiangolo.com/)
- [PyJWT](https://pyjwt.readthedocs.io/)
- [Pydantic](https://pydantic-docs.helpmanual.io/)
- [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/)
