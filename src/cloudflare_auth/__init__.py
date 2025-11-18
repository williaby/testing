"""Cloudflare Access authentication middleware and utilities.

This module provides comprehensive authentication handling for applications
behind Cloudflare Access tunnels, including:

- JWT token validation (secure)
- Email whitelist with domain support
- User tiers (admin/full/limited)
- Session management
- Development mode support

Quick Start:
    from fastapi import FastAPI, Depends
    from src.cloudflare_auth import (
        setup_cloudflare_auth_enhanced,
        CloudflareUser,
        get_current_user,
        require_admin
    )

    app = FastAPI()

    setup_cloudflare_auth_enhanced(
        app,
        whitelist=["user@example.com", "@company.com"],
        admin_emails=["admin@company.com"]
    )

    @app.get("/protected")
    async def protected(user: CloudflareUser = Depends(get_current_user)):
        return {"email": user.email, "tier": user.user_tier.value}

    @app.get("/admin")
    async def admin(user: CloudflareUser = Depends(require_admin)):
        return {"message": "Admin access granted"}
"""

from src.cloudflare_auth.middleware import CloudflareAuthMiddleware, get_current_user, get_current_user_optional
from src.cloudflare_auth.middleware_enhanced import (
    CloudflareAuthMiddlewareEnhanced,
    require_admin,
    require_tier,
    setup_cloudflare_auth_enhanced,
)
from src.cloudflare_auth.models import CloudflareJWTClaims, CloudflareUser
from src.cloudflare_auth.security_helpers import (
    AuditLogger,
    SecurityHeadersMiddleware,
    create_session_cleanup_task,
    get_audit_logger,
)
from src.cloudflare_auth.sessions import SimpleSessionManager
from src.cloudflare_auth.validators import CloudflareJWTValidator
from src.cloudflare_auth.whitelist import (
    EmailWhitelistValidator,
    UserTier,
    WhitelistManager,
    create_validator_from_env,
)

# Optional Redis session manager (requires redis package)
try:
    from src.cloudflare_auth.redis_sessions import RedisSessionManager
    _REDIS_AVAILABLE = True
except ImportError:
    RedisSessionManager = None  # type: ignore
    _REDIS_AVAILABLE = False

__all__ = [
    # Middleware
    "CloudflareAuthMiddleware",
    "CloudflareAuthMiddlewareEnhanced",
    "setup_cloudflare_auth_enhanced",
    # Models
    "CloudflareUser",
    "CloudflareJWTClaims",
    "UserTier",
    # Validators
    "CloudflareJWTValidator",
    "EmailWhitelistValidator",
    # Sessions
    "SimpleSessionManager",
    # Whitelist Management
    "WhitelistManager",
    "create_validator_from_env",
    # Security Helpers
    "SecurityHeadersMiddleware",
    "AuditLogger",
    "get_audit_logger",
    "create_session_cleanup_task",
    # Dependencies
    "get_current_user",
    "get_current_user_optional",
    "require_admin",
    "require_tier",
]

# Add RedisSessionManager if available
if _REDIS_AVAILABLE and RedisSessionManager is not None:
    __all__.append("RedisSessionManager")
