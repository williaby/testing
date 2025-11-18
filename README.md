# Cloudflare Access Authentication for FastAPI

A comprehensive, production-ready authentication middleware for FastAPI applications using Cloudflare Access tunnels. This module handles JWT validation, user authentication, and provides a seamless integration with Cloudflare's Zero Trust security model.

## Features

- **JWT Token Validation**: Automatic validation using Cloudflare's public certificates
- **User Authentication**: Extract and validate user information from Cloudflare headers
- **Flexible Configuration**: Environment-based settings with Pydantic
- **Email Domain Restrictions**: Optional whitelist for allowed email domains
- **Path Exclusions**: Easily exclude public endpoints from authentication
- **Dependency Injection**: FastAPI-native user access via dependencies
- **Comprehensive Logging**: Security event logging with sensitive data masking
- **Type Safety**: Full type hints and Pydantic models
- **Production Ready**: Includes caching, error handling, and security best practices

## Quick Start

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Configuration

Copy the example environment file and configure your Cloudflare settings:

```bash
cp examples/.env.example .env
```

Edit `.env` with your Cloudflare Access configuration:

```env
CLOUDFLARE_TEAM_DOMAIN=your-team.cloudflareaccess.com
CLOUDFLARE_AUDIENCE_TAG=your-audience-tag-from-cloudflare
CLOUDFLARE_ENABLED=true
```

### 3. Basic Usage

```python
from fastapi import FastAPI, Depends
from src.cloudflare_auth import setup_cloudflare_auth, CloudflareUser
from src.cloudflare_auth.middleware import get_current_user

app = FastAPI()

# Setup Cloudflare authentication
setup_cloudflare_auth(app)

@app.get("/protected")
async def protected_route(user: CloudflareUser = Depends(get_current_user)):
    return {"email": user.email, "user_id": user.user_id}
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLOUDFLARE_TEAM_DOMAIN` | Yes | - | Your Cloudflare team domain (e.g., `myteam.cloudflareaccess.com`) |
| `CLOUDFLARE_AUDIENCE_TAG` | Yes | - | Application audience tag from Cloudflare dashboard |
| `CLOUDFLARE_ENABLED` | No | `true` | Enable/disable authentication (useful for local dev) |
| `ALLOWED_EMAIL_DOMAINS` | No | `[]` | Comma-separated list of allowed email domains |
| `ENVIRONMENT` | No | `dev` | Environment: `dev`, `staging`, or `prod` |
| `REQUIRE_EMAIL_VERIFICATION` | No | `true` | Require verified email in JWT claims |
| `LOG_AUTH_FAILURES` | No | `true` | Log authentication failures |

### Finding Your Cloudflare Configuration

1. **Team Domain**: Go to Cloudflare Zero Trust dashboard → Settings → Custom Pages. Your team domain is shown at the top.

2. **Audience Tag**: Go to Access → Applications → Select your application → Overview. The "Application Audience (AUD) Tag" is displayed in the application details.

## Usage Examples

### Basic Protected Endpoint

```python
from fastapi import Request

@app.get("/api/data")
async def get_data(request: Request):
    user = request.state.user  # CloudflareUser object
    return {"data": "sensitive", "user": user.email}
```

### Using Dependency Injection

```python
from fastapi import Depends
from src.cloudflare_auth import CloudflareUser
from src.cloudflare_auth.middleware import get_current_user

@app.get("/me")
async def get_me(user: CloudflareUser = Depends(get_current_user)):
    return {
        "email": user.email,
        "user_id": user.user_id,
        "domain": user.email_domain,
    }
```

### Optional Authentication

```python
from src.cloudflare_auth.middleware import get_current_user_optional

@app.get("/optional")
async def optional_auth(
    user: CloudflareUser | None = Depends(get_current_user_optional)
):
    if user:
        return {"message": f"Hello {user.email}"}
    return {"message": "Hello anonymous user"}
```

### Email Domain Restrictions

```python
@app.get("/admin")
async def admin_only(user: CloudflareUser = Depends(get_current_user)):
    if not user.has_email_domain("example.com"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"message": "Admin panel"}
```

### Excluding Paths from Authentication

```python
from src.cloudflare_auth import setup_cloudflare_auth

setup_cloudflare_auth(
    app,
    excluded_paths=[
        "/health",      # Health checks
        "/metrics",     # Prometheus metrics
        "/docs",        # API documentation
        "/public",      # Public endpoints
    ]
)
```

## Advanced Usage

### Custom Role-Based Access Control

See `examples/advanced_usage.py` for a complete example with:
- Email domain-based authorization
- Specific user restrictions
- Custom decorators for access control

### Manual Token Validation

```python
from src.cloudflare_auth import CloudflareJWTValidator

validator = CloudflareJWTValidator()

try:
    claims = validator.validate_token(jwt_token)
    print(f"User: {claims.email}")
except ValueError as e:
    print(f"Invalid token: {e}")
```

### Accessing JWT Claims

```python
@app.get("/claims")
async def get_claims(user: CloudflareUser = Depends(get_current_user)):
    return {
        "email": user.email,
        "issuer": user.claims.iss,
        "audience": user.claims.get_audience_list(),
        "issued_at": user.claims.issued_at,
        "expires_at": user.claims.expires_at,
    }
```

## Architecture

### Components

1. **CloudflareSettings** (`src/config/settings.py`)
   - Pydantic-based configuration management
   - Environment variable loading
   - Validation and defaults

2. **CloudflareUser** (`src/cloudflare_auth/models.py`)
   - User model with email and ID
   - Access to full JWT claims
   - Helper methods for domain checking

3. **CloudflareJWTValidator** (`src/cloudflare_auth/validators.py`)
   - JWT signature verification
   - Certificate caching
   - Claims validation

4. **CloudflareAuthMiddleware** (`src/cloudflare_auth/middleware.py`)
   - ASGI middleware for FastAPI
   - Request authentication
   - User object injection

### Request Flow

```
Client Request
    ↓
Cloudflare Access (authenticates user)
    ↓
CloudflareAuthMiddleware
    ├─ Extract JWT from Cf-Access-Jwt-Assertion header
    ├─ Validate JWT signature
    ├─ Verify claims (audience, issuer, expiration)
    ├─ Create CloudflareUser object
    └─ Attach to request.state.user
    ↓
Your Application Endpoint
    ↓
Response
```

## Security Considerations

1. **Always use HTTPS** - Cloudflare Access requires HTTPS
2. **Validate audience tag** - Ensures tokens are for your application
3. **Check email domains** - Use `ALLOWED_EMAIL_DOMAINS` for additional restrictions
4. **Log auth failures** - Monitor for potential security issues
5. **Exclude only necessary paths** - Minimize public endpoints
6. **Use in production** - Set `ENVIRONMENT=prod` for stricter security

## Development

### Local Development Without Cloudflare

For local development without Cloudflare Access:

```env
CLOUDFLARE_ENABLED=false
```

The middleware will bypass authentication in this mode.

### Testing

Create test utilities for mocking Cloudflare authentication:

```python
from src.cloudflare_auth.models import CloudflareUser, CloudflareJWTClaims

# Create a mock user for testing
test_claims = CloudflareJWTClaims(
    email="test@example.com",
    iss="https://test.cloudflareaccess.com",
    aud=["test-audience"],
    sub="test-user-123",
    iat=1234567890,
    exp=1234571490,
)

test_user = CloudflareUser.from_jwt_claims(test_claims)
```

### Running Examples

```bash
# Basic example
python examples/basic_usage.py

# Advanced example with RBAC
python examples/advanced_usage.py
```

Visit `http://localhost:8000/docs` for interactive API documentation.

## Cloudflare Access Setup

### 1. Create a Cloudflare Access Application

1. Go to Cloudflare Zero Trust dashboard
2. Navigate to Access → Applications
3. Click "Add an application"
4. Choose "Self-hosted"
5. Configure:
   - Application name
   - Session duration
   - Application domain

### 2. Configure Authentication

1. Add authentication methods (Google, Azure AD, etc.)
2. Create access policies:
   - Allow specific users
   - Allow email domains
   - Require multi-factor authentication

### 3. Get Configuration Values

1. **Audience Tag**: Copy from application overview
2. **Team Domain**: Found in dashboard settings
3. Add these to your `.env` file

### 4. Configure Your Application

1. Point your Cloudflare tunnel to your application
2. Ensure your application trusts the `Cf-Access-Jwt-Assertion` header
3. Test authentication with a whitelisted user

## Troubleshooting

### "Missing Cloudflare JWT header"

- Ensure the application is behind Cloudflare Access
- Check that the tunnel is properly configured
- Verify the path is not in `excluded_paths`

### "Invalid token signature"

- Verify `CLOUDFLARE_TEAM_DOMAIN` is correct
- Check that the audience tag matches
- Ensure system time is synchronized (for token expiration)

### "Email domain not allowed"

- Check `ALLOWED_EMAIL_DOMAINS` configuration
- Ensure the user's email domain is in the whitelist
- Remove domain restrictions if not needed

### Authentication works but user is None

- Ensure middleware is added before routes
- Check that `require_auth=True` in `setup_cloudflare_auth()`
- Verify the path is not excluded

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Maintain type hints for all functions
2. Add comprehensive docstrings
3. Include examples for new features
4. Update README with new configuration options

## License

MIT License - feel free to use in your projects!

## Support

For issues and questions:
1. Check the examples in `examples/`
2. Review Cloudflare Access documentation
3. Check application logs for authentication errors

## Acknowledgments

Built for use with:
- [Cloudflare Access](https://www.cloudflare.com/products/zero-trust/access/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [PyJWT](https://pyjwt.readthedocs.io/)
