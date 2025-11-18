# Security Best Practices

This document outlines security best practices when using this Cloudflare Access authentication module in your projects.

## Table of Contents

1. [Production Deployment](#production-deployment)
2. [Configuration Security](#configuration-security)
3. [Session Management](#session-management)
4. [Monitoring and Logging](#monitoring-and-logging)
5. [Rate Limiting](#rate-limiting)
6. [Dependency Management](#dependency-management)
7. [Code Security](#code-security)
8. [Incident Response](#incident-response)

## Production Deployment

### ✅ DO

1. **Use pinned dependencies**
   ```bash
   pip install -r requirements-pinned.txt
   ```

2. **Enable HTTPS only**
   - Configure your Cloudflare tunnel with HTTPS
   - Never expose the app directly without Cloudflare

3. **Use security headers**
   ```python
   from src.cloudflare_auth import SecurityHeadersMiddleware

   app.add_middleware(SecurityHeadersMiddleware, enable_hsts=True)
   ```

4. **Enable session cleanup**
   ```python
   from src.cloudflare_auth import create_session_cleanup_task

   @app.on_event("startup")
   async def startup():
       app.state.cleanup_task = create_session_cleanup_task(
           session_manager,
           cleanup_interval=300  # 5 minutes
       )
   ```

5. **Configure proper logging**
   ```python
   import logging

   logging.basicConfig(
       level=logging.INFO,
       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
       handlers=[
           logging.FileHandler('app.log'),
           logging.StreamHandler()
       ]
   )
   ```

### ❌ DON'T

1. **Don't disable Cloudflare auth in production**
   ```python
   # NEVER do this in production
   CLOUDFLARE_ENABLED=false
   ```

2. **Don't use development settings**
   ```python
   # WRONG for production
   ENVIRONMENT=dev
   ```

3. **Don't expose sensitive endpoints**
   ```python
   # Be careful with excluded_paths
   excluded_paths=["/admin", "/api"]  # BAD!
   ```

4. **Don't log sensitive data**
   ```python
   # WRONG
   logger.info(f"JWT token: {jwt_token}")

   # RIGHT
   logger.info(f"User authenticated: {user.email}")
   ```

## Configuration Security

### Environment Variables

1. **Store securely**
   - Use `.env` files (gitignored)
   - Use environment variable managers (AWS Secrets Manager, etc.)
   - Never commit secrets to git

2. **Rotate regularly**
   ```bash
   # Rotate Cloudflare audience tags periodically
   CLOUDFLARE_AUDIENCE_TAG=new-audience-tag-here
   ```

3. **Use strong whitelists**
   ```env
   # Good: Specific domain
   WHITELIST=@yourcompany.com,admin@example.com

   # Bad: Public domains
   WHITELIST=@gmail.com,@outlook.com  # INSECURE!
   ```

### Example Secure Configuration

```env
# Production .env file
ENVIRONMENT=prod
CLOUDFLARE_ENABLED=true
CLOUDFLARE_TEAM_DOMAIN=yourteam.cloudflareaccess.com
CLOUDFLARE_AUDIENCE_TAG=<your-secure-tag>

# Whitelist
WHITELIST=@yourcompany.com
ADMIN_EMAILS=admin@yourcompany.com,cto@yourcompany.com
FULL_USERS=@yourcompany.com
LIMITED_USERS=contractor@partner.com

# Sessions
ENABLE_SESSIONS=true
SESSION_TIMEOUT=3600  # 1 hour

# Security
REQUIRE_EMAIL_VERIFICATION=true
LOG_AUTH_FAILURES=true
```

## Session Management

### In-Memory Sessions (Development/Single Instance)

```python
from src.cloudflare_auth import SimpleSessionManager

session_manager = SimpleSessionManager(session_timeout=3600)
```

**Limitations:**
- Sessions lost on restart
- Not suitable for load balancers
- Memory grows over time without cleanup

**Solutions:**
```python
# Add background cleanup
task = create_session_cleanup_task(session_manager, cleanup_interval=300)
```

### Redis Sessions (Production/Multi-Instance)

For production with multiple instances, implement Redis backend:

```python
import redis
from src.cloudflare_auth.sessions import SimpleSessionManager

class RedisSessionManager(SimpleSessionManager):
    def __init__(self, redis_url: str, session_timeout: int = 3600):
        self.redis = redis.from_url(redis_url)
        super().__init__(session_timeout)

    def create_session(self, email: str, is_admin: bool, user_tier: str, cf_context=None):
        session_id = super().create_session(email, is_admin, user_tier, cf_context)
        # Store in Redis
        self.redis.setex(
            f"session:{session_id}",
            self.session_timeout,
            json.dumps(self.sessions[session_id], default=str)
        )
        return session_id

    def get_session(self, session_id: str):
        # Get from Redis
        data = self.redis.get(f"session:{session_id}")
        if data:
            return json.loads(data)
        return None
```

## Monitoring and Logging

### Audit Logging

```python
from src.cloudflare_auth import get_audit_logger

audit = get_audit_logger()

# Log admin actions
audit.log_admin_action(
    admin_email="admin@company.com",
    action="delete_user",
    target="user@example.com",
    result="success"
)

# Log security events
audit.log_security_event(
    event_type="suspicious_login",
    severity="high",
    description="Multiple failed login attempts",
    details={"ip": "192.168.1.100", "attempts": 5}
)
```

### Metrics to Monitor

1. **Authentication metrics**
   - Failed authentication attempts
   - Successful authentications
   - Authentication latency

2. **Session metrics**
   - Active sessions count
   - Session creation rate
   - Expired sessions cleaned

3. **Security metrics**
   - Admin actions
   - Access denials
   - Tier upgrades/downgrades

### Example Monitoring Setup

```python
from prometheus_client import Counter, Histogram, Gauge

# Define metrics
auth_attempts = Counter('auth_attempts_total', 'Total authentication attempts', ['result'])
auth_latency = Histogram('auth_duration_seconds', 'Authentication duration')
active_sessions = Gauge('active_sessions', 'Number of active sessions')

# Use in middleware
@auth_latency.time()
async def authenticate():
    try:
        user = await authenticate_request(request)
        auth_attempts.labels(result='success').inc()
        return user
    except Exception:
        auth_attempts.labels(result='failure').inc()
        raise
```

## Rate Limiting

### slowapi Integration

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/protected")
@limiter.limit("100/minute")
async def protected(request: Request, user: CloudflareUser = Depends(get_current_user)):
    return {"user": user.email}
```

### Custom Rate Limiting

```python
from collections import defaultdict
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, max_requests: int, window: int):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window)
        self.requests = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = datetime.now()
        # Clean old requests
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if now - req_time < self.window
        ]

        if len(self.requests[key]) >= self.max_requests:
            return False

        self.requests[key].append(now)
        return True

# Usage
rate_limiter = RateLimiter(max_requests=100, window=60)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    if not rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"}
        )
    return await call_next(request)
```

## Dependency Management

### Security Updates

1. **Regular updates**
   ```bash
   # Check for updates
   pip list --outdated

   # Update dependencies
   pip install --upgrade -r requirements.txt

   # Test thoroughly
   pytest
   ```

2. **Security scanning**
   ```bash
   # Scan for vulnerabilities
   bandit -r src/

   # Check dependencies (if safety works)
   # safety check --file requirements.txt
   ```

3. **Pinning strategy**
   ```txt
   # Development: Use >= for flexibility
   PyJWT[crypto]>=2.8.0

   # Production: Use == for stability
   PyJWT[crypto]==2.9.0
   ```

### Verified Versions

Current verified secure versions:
```
PyJWT[crypto]==2.9.0
cryptography==43.0.3
FastAPI==0.115.0
Pydantic==2.9.2
httpx==0.27.2
```

## Code Security

### Input Validation

```python
from pydantic import BaseModel, EmailStr, validator

class UserCreate(BaseModel):
    email: EmailStr
    tier: str

    @validator('tier')
    def validate_tier(cls, v):
        allowed = ['admin', 'full', 'limited']
        if v not in allowed:
            raise ValueError(f'Tier must be one of: {allowed}')
        return v

@app.post("/users")
async def create_user(user_data: UserCreate):
    # Input is validated by Pydantic
    pass
```

### SQL Injection Prevention

```python
# If using database, always use parameterized queries
# WRONG
query = f"SELECT * FROM users WHERE email = '{email}'"

# RIGHT
query = "SELECT * FROM users WHERE email = ?"
cursor.execute(query, (email,))
```

### XSS Prevention

```python
# FastAPI automatically escapes JSON responses
# For HTML responses, use proper escaping
from markupsafe import escape

@app.get("/user/{email}")
async def get_user_page(email: str):
    safe_email = escape(email)
    return HTMLResponse(f"<h1>User: {safe_email}</h1>")
```

## Incident Response

### Security Incident Checklist

1. **Detect**
   - Monitor logs for anomalies
   - Set up alerts for failed auth attempts
   - Track unusual admin actions

2. **Respond**
   ```python
   # Immediately invalidate sessions
   session_manager.invalidate_session(compromised_session_id)

   # Temporarily disable user
   whitelist_manager.remove_email(compromised_email)

   # Log incident
   audit.log_security_event(
       event_type="security_incident",
       severity="critical",
       description="Compromised account detected",
       details={"user": compromised_email, "action": "account_disabled"}
   )
   ```

3. **Recover**
   - Rotate Cloudflare audience tags
   - Update whitelist
   - Review and patch vulnerabilities
   - Document incident

4. **Learn**
   - Conduct post-mortem
   - Update security procedures
   - Improve monitoring

### Emergency Procedures

```python
# Emergency lockdown (disable all access)
@app.post("/emergency/lockdown")
async def emergency_lockdown(admin: CloudflareUser = Depends(require_admin)):
    # Disable authentication
    os.environ["CLOUDFLARE_ENABLED"] = "false"

    # Log critical event
    audit.log_security_event(
        event_type="emergency_lockdown",
        severity="critical",
        description=f"Emergency lockdown initiated by {admin.email}"
    )

    return {"status": "lockdown_active"}
```

## Security Checklist

Before deploying to production:

- [ ] Pin all dependency versions
- [ ] Enable HTTPS only
- [ ] Configure proper whitelists
- [ ] Enable session cleanup
- [ ] Add security headers
- [ ] Implement rate limiting
- [ ] Set up monitoring and alerting
- [ ] Configure audit logging
- [ ] Test authentication flow
- [ ] Review excluded paths
- [ ] Rotate secrets regularly
- [ ] Document incident response
- [ ] Train team on security procedures
- [ ] Set up backup authentication
- [ ] Configure log retention
- [ ] Enable security scanning in CI/CD

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Cloudflare Access Documentation](https://developers.cloudflare.com/cloudflare-one/applications/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Python Security](https://python.readthedocs.io/en/stable/library/security_warnings.html)

## Contact

For security concerns or vulnerabilities:
- Review code before deployment
- Run security scans regularly
- Keep dependencies updated
- Follow security best practices
