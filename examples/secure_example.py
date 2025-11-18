"""Production-ready secure example with all security features enabled.

This example demonstrates a production-ready setup with:
- JWT validation
- Email whitelist
- User tiers
- Session management
- Security headers
- Session cleanup
- Audit logging
- Rate limiting (via slowapi)

Use this as a template for production deployments.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from src.cloudflare_auth import (
    CloudflareUser,
    UserTier,
    get_current_user,
    require_admin,
    setup_cloudflare_auth_enhanced,
)
from src.cloudflare_auth.security_helpers import (
    AuditLogger,
    SecurityHeadersMiddleware,
    create_session_cleanup_task,
    get_audit_logger,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Initialize audit logger
audit = get_audit_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager with session cleanup."""
    logger.info("Starting secure production application...")

    # Start session cleanup background task
    cleanup_task = create_session_cleanup_task(
        app.state.session_manager,
        cleanup_interval=300  # 5 minutes
    )
    app.state.cleanup_task = cleanup_task

    yield

    # Cleanup on shutdown
    logger.info("Shutting down application...")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


# Create FastAPI app
app = FastAPI(
    title="Secure Cloudflare Auth Example",
    description="Production-ready example with all security features",
    version="2.0.0",
    lifespan=lifespan,
)

# Setup enhanced Cloudflare authentication
middleware = setup_cloudflare_auth_enhanced(
    app,
    whitelist=[
        "user@example.com",
        "@company.com",
    ],
    admin_emails=[
        "admin@company.com",
    ],
    full_users=[
        "@company.com",
    ],
    limited_users=[
        "contractor@external.com",
    ],
    excluded_paths=[
        "/",
        "/health",
        "/metrics",
    ],
    enable_sessions=True,
    session_timeout=3600,
    require_auth=True,
)

# Store session manager for cleanup task
if middleware and hasattr(middleware, "session_manager"):
    app.state.session_manager = middleware.session_manager

# Add security headers middleware
app.add_middleware(
    SecurityHeadersMiddleware,
    enable_hsts=True,  # Enable HSTS for production
)

# Optional: Add rate limiting
# Uncomment if you install slowapi
# from slowapi import Limiter, _rate_limit_exceeded_handler
# from slowapi.util import get_remote_address
# from slowapi.errors import RateLimitExceeded
#
# limiter = Limiter(key_func=get_remote_address)
# app.state.limiter = limiter
# app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ============================================================================
# PUBLIC ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Public root endpoint."""
    return {
        "message": "Secure Production Application",
        "security_features": [
            "JWT validation with RS256",
            "Email whitelist authorization",
            "User tier management",
            "Session management with HttpOnly cookies",
            "Security headers (CSP, HSTS, etc.)",
            "Automatic session cleanup",
            "Audit logging",
            "JWT size validation",
        ],
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "security": "enabled"
    }


@app.get("/metrics")
async def metrics(request: Request):
    """Metrics endpoint (public for monitoring)."""
    session_manager = getattr(app.state, "session_manager", None)

    metrics_data = {
        "app": "cloudflare_auth_secure",
        "status": "running",
    }

    if session_manager:
        stats = session_manager.get_stats()
        metrics_data["sessions"] = stats

    return metrics_data


# ============================================================================
# AUTHENTICATED ENDPOINTS
# ============================================================================

@app.get("/protected")
async def protected_endpoint(
    request: Request,
    user: CloudflareUser = Depends(get_current_user)
):
    """Protected endpoint with audit logging."""
    # Log access
    audit.log_auth_event(
        event_type="access",
        user_email=user.email,
        ip_address=request.client.host if request.client else None,
        details={"path": "/protected"}
    )

    return {
        "message": "You are authenticated",
        "user": user.model_dump_safe(),
    }


@app.get("/premium")
async def premium_endpoint(
    request: Request,
    user: CloudflareUser = Depends(get_current_user)
):
    """Premium endpoint - tier checking with audit logging."""
    # Check tier
    if not user.can_access_premium_models:
        # Log access denial
        audit.log_access_denied(
            user_email=user.email,
            resource="/premium",
            reason=f"insufficient_tier_{user.user_tier.value}",
            ip_address=request.client.host if request.client else None
        )

        return JSONResponse(
            status_code=403,
            content={"detail": "Premium tier required"}
        )

    # Log successful access
    audit.log_auth_event(
        event_type="premium_access",
        user_email=user.email,
        ip_address=request.client.host if request.client else None,
        details={"path": "/premium", "tier": user.user_tier.value}
    )

    return {
        "message": "Premium access granted",
        "tier": user.user_tier.value,
        "premium_features": ["GPT-4", "Claude-3", "Priority support"]
    }


# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

@app.get("/admin")
async def admin_panel(
    request: Request,
    user: CloudflareUser = Depends(require_admin)
):
    """Admin panel with audit logging."""
    # Log admin access
    audit.log_auth_event(
        event_type="admin_access",
        user_email=user.email,
        ip_address=request.client.host if request.client else None,
        details={"path": "/admin"}
    )

    return {
        "message": "Admin panel",
        "admin": user.email,
    }


@app.post("/admin/users")
async def create_user(
    request: Request,
    user: CloudflareUser = Depends(require_admin)
):
    """Create user with audit logging."""
    body = await request.json()

    target_email = body.get("email")

    # Log admin action
    audit.log_admin_action(
        admin_email=user.email,
        action="create_user",
        target=target_email,
        result="success",
        details={
            "tier": body.get("tier", "limited"),
            "ip": request.client.host if request.client else None
        }
    )

    logger.info("User %s created by admin %s", target_email, user.email)

    return {
        "message": "User created successfully",
        "created_by": user.email,
        "user": body,
    }


@app.delete("/admin/users/{email}")
async def delete_user(
    email: str,
    request: Request,
    user: CloudflareUser = Depends(require_admin)
):
    """Delete user with audit logging."""
    # Log admin action
    audit.log_admin_action(
        admin_email=user.email,
        action="delete_user",
        target=email,
        result="success",
        details={
            "ip": request.client.host if request.client else None
        }
    )

    logger.warning("User %s deleted by admin %s", email, user.email)

    return {
        "message": "User deleted",
        "deleted_by": user.email,
        "deleted_user": email,
    }


@app.get("/admin/audit-log")
async def get_audit_log(
    request: Request,
    user: CloudflareUser = Depends(require_admin)
):
    """Get audit log (admin only)."""
    # Log access to audit log
    audit.log_admin_action(
        admin_email=user.email,
        action="view_audit_log",
        result="success"
    )

    # In production, this would query a database
    return {
        "message": "Audit log access",
        "note": "In production, this would return actual audit entries from database",
        "accessed_by": user.email,
    }


@app.get("/admin/sessions")
async def get_sessions(
    user: CloudflareUser = Depends(require_admin)
):
    """Get session statistics (admin only)."""
    session_manager = getattr(app.state, "session_manager", None)

    if not session_manager:
        return {"error": "Session manager not available"}

    stats = session_manager.get_stats()

    # Log admin action
    audit.log_admin_action(
        admin_email=user.email,
        action="view_sessions",
        result="success",
        details=stats
    )

    return {
        "sessions": stats,
        "requested_by": user.email,
    }


# ============================================================================
# SECURITY EVENT LOGGING EXAMPLES
# ============================================================================

@app.post("/report-suspicious")
async def report_suspicious(
    request: Request,
    user: CloudflareUser = Depends(get_current_user)
):
    """Example endpoint for reporting suspicious activity."""
    body = await request.json()

    # Log security event
    audit.log_security_event(
        event_type="user_reported_suspicious",
        severity="medium",
        description=f"User {user.email} reported suspicious activity",
        details={
            "reporter": user.email,
            "report": body,
            "ip": request.client.host if request.client else None
        }
    )

    return {
        "message": "Report received",
        "status": "investigating"
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with security logging."""
    logger.error(
        "Unhandled exception: %s (path: %s)",
        exc,
        request.url.path,
        exc_info=True
    )

    # Log security event for unexpected errors
    audit.log_security_event(
        event_type="unexpected_error",
        severity="high",
        description=f"Unhandled exception in {request.url.path}",
        details={
            "error": str(exc),
            "path": request.url.path,
            "method": request.method
        }
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "path": str(request.url.path)
        }
    )


if __name__ == "__main__":
    import uvicorn

    # Production configuration
    # Make sure to set environment variables:
    # - CLOUDFLARE_TEAM_DOMAIN
    # - CLOUDFLARE_AUDIENCE_TAG
    # - WHITELIST
    # - ADMIN_EMAILS
    # - etc.

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        # Production settings:
        # - Use uvicorn with gunicorn for production
        # - Enable SSL/TLS
        # - Configure proper logging
        # - Set up monitoring and alerts
    )
