"""Complete example with JWT validation, whitelist, sessions, and tiers.

This example demonstrates the full power of the enhanced Cloudflare
authentication system:

- JWT token validation (cryptographically secure)
- Email whitelist with domain support (@company.com)
- User tiers (admin/full/limited) for access control
- Session management with cookies
- Premium model access based on tier
- Admin-only endpoints

Run this example:
    1. Set environment variables (see .env.example)
    2. python examples/complete_example.py
    3. Access via your Cloudflare-protected domain
"""

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from src.cloudflare_auth import (
    CloudflareUser,
    UserTier,
    get_current_user,
    require_admin,
    require_tier,
    setup_cloudflare_auth_enhanced,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager."""
    logging.info("Starting complete example application...")
    yield
    logging.info("Shutting down application...")


# Create FastAPI app
app = FastAPI(
    title="Complete Cloudflare Auth Example",
    description="Full-featured example with JWT, whitelist, sessions, and tiers",
    version="2.0.0",
    lifespan=lifespan,
)

# Setup enhanced Cloudflare authentication
# This combines ALL features:
# - JWT validation for security
# - Email whitelist authorization
# - User tiers for access control
# - Session management
setup_cloudflare_auth_enhanced(
    app,
    whitelist=[
        "user@example.com",  # Individual user
        "@company.com",      # All users from company.com domain
    ],
    admin_emails=[
        "admin@company.com",
        "boss@company.com",
    ],
    full_users=[
        "@company.com",  # All company users get full access
    ],
    limited_users=[
        "contractor@external.com",  # External contractors are limited
    ],
    excluded_paths=[
        "/",
        "/health",
        "/public",
    ],
    enable_sessions=True,  # Enable session cookies
    session_timeout=3600,  # 1 hour sessions
    require_auth=True,
)


# ============================================================================
# PUBLIC ENDPOINTS (no authentication required)
# ============================================================================

@app.get("/")
async def root():
    """Public root endpoint."""
    return {
        "message": "Complete Cloudflare Auth Example",
        "features": [
            "JWT token validation",
            "Email whitelist (@domain.com support)",
            "User tiers (admin/full/limited)",
            "Session management",
            "Premium model access control"
        ],
        "endpoints": {
            "public": "/public",
            "authenticated": "/protected",
            "premium": "/premium (requires full/admin tier)",
            "admin": "/admin (requires admin tier)",
        },
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/public")
async def public_endpoint():
    """Public endpoint - no auth required."""
    return {"message": "This endpoint is public"}


# ============================================================================
# AUTHENTICATED ENDPOINTS (requires any tier)
# ============================================================================

@app.get("/protected")
async def protected_endpoint(user: CloudflareUser = Depends(get_current_user)):
    """Protected endpoint - requires authentication."""
    return {
        "message": "You are authenticated",
        "user": {
            "email": user.email,
            "tier": user.user_tier.value,
            "is_admin": user.is_admin,
            "can_access_premium": user.can_access_premium_models,
        }
    }


@app.get("/me")
async def get_user_profile(user: CloudflareUser = Depends(get_current_user)):
    """Get current user profile."""
    return {
        "profile": {
            "email": user.email,
            "user_id": user.user_id,
            "email_domain": user.email_domain,
            "email_username": user.email_username,
        },
        "access": {
            "tier": user.user_tier.value,
            "is_admin": user.is_admin,
            "role": user.role,
            "can_access_premium": user.can_access_premium_models,
        },
        "session": {
            "authenticated_at": user.authenticated_at.isoformat(),
            "has_session": user.session_id is not None,
        },
        "jwt": {
            "issuer": user.claims.iss,
            "expires_at": user.claims.expires_at.isoformat(),
        }
    }


# ============================================================================
# PREMIUM ENDPOINTS (requires full or admin tier)
# ============================================================================

# Create a dependency for full+ tiers
require_full = require_tier(UserTier.FULL)


@app.get("/premium")
async def premium_endpoint(user: CloudflareUser = Depends(require_full)):
    """Premium endpoint - requires full or admin tier."""
    return {
        "message": "Welcome to premium features",
        "user": user.email,
        "tier": user.user_tier.value,
        "features": [
            "Premium models (GPT-4, Claude, etc.)",
            "Higher rate limits",
            "Priority support",
            "Advanced analytics"
        ]
    }


@app.get("/premium/models")
async def premium_models(user: CloudflareUser = Depends(require_full)):
    """Get available premium models."""
    if user.can_access_premium_models:
        return {
            "available_models": [
                "gpt-4-turbo",
                "gpt-4",
                "claude-3-opus",
                "claude-3-sonnet",
                "gemini-pro",
            ],
            "user_tier": user.user_tier.value,
        }
    else:
        return JSONResponse(
            status_code=403,
            content={"detail": "Premium models require full or admin tier"}
        )


# ============================================================================
# ADMIN ENDPOINTS (requires admin tier)
# ============================================================================

@app.get("/admin")
async def admin_panel(user: CloudflareUser = Depends(require_admin)):
    """Admin panel - requires admin privileges."""
    return {
        "message": "Welcome to the admin panel",
        "admin": user.email,
        "capabilities": [
            "User management",
            "System configuration",
            "Analytics dashboard",
            "Audit logs"
        ]
    }


@app.get("/admin/users")
async def list_users(user: CloudflareUser = Depends(require_admin)):
    """List all users (admin only)."""
    # In a real app, this would query your database
    return {
        "users": [
            {"email": "user@example.com", "tier": "full"},
            {"email": "admin@company.com", "tier": "admin"},
            {"email": "contractor@external.com", "tier": "limited"},
        ],
        "requested_by": user.email,
    }


@app.post("/admin/users")
async def create_user(
    request: Request,
    user: CloudflareUser = Depends(require_admin)
):
    """Create a new user (admin only)."""
    body = await request.json()

    logging.info("User creation requested by %s: %s", user.email, body)

    return {
        "message": "User created successfully",
        "created_by": user.email,
        "data": body,
    }


@app.get("/admin/stats")
async def get_stats(user: CloudflareUser = Depends(require_admin)):
    """Get system statistics (admin only)."""
    # In a real app, this would query your analytics
    return {
        "system": {
            "total_users": 150,
            "active_sessions": 42,
            "requests_today": 15234,
        },
        "tiers": {
            "admin": 3,
            "full": 120,
            "limited": 27,
        },
        "requested_by": user.email,
    }


# ============================================================================
# TIER-SPECIFIC EXAMPLES
# ============================================================================

@app.get("/user-tier-info")
async def get_tier_info(user: CloudflareUser = Depends(get_current_user)):
    """Get information about your tier."""
    tier_info = {
        UserTier.ADMIN: {
            "name": "Administrator",
            "description": "Full system access plus administrative privileges",
            "features": [
                "Premium model access",
                "User management",
                "System configuration",
                "Unlimited rate limits",
                "Priority support"
            ]
        },
        UserTier.FULL: {
            "name": "Full Access",
            "description": "Full access to all features",
            "features": [
                "Premium model access",
                "High rate limits",
                "Standard support",
                "Advanced analytics"
            ]
        },
        UserTier.LIMITED: {
            "name": "Limited Access",
            "description": "Basic access with restrictions",
            "features": [
                "Basic models only",
                "Standard rate limits",
                "Community support"
            ]
        }
    }

    return {
        "your_tier": user.user_tier.value,
        "tier_info": tier_info[user.user_tier],
        "can_upgrade": user.user_tier == UserTier.LIMITED,
    }


# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

@app.post("/logout")
async def logout(request: Request, user: CloudflareUser = Depends(get_current_user)):
    """Logout and invalidate session."""
    # In a real app, you would invalidate the session here
    response = JSONResponse(content={"message": "Logged out successfully"})

    # Clear session cookie
    response.delete_cookie("session_id")

    logging.info("User %s logged out", user.email)

    return response


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logging.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "path": str(request.url.path)
        }
    )


if __name__ == "__main__":
    import uvicorn

    # Make sure to set these environment variables:
    # - CLOUDFLARE_TEAM_DOMAIN=your-team.cloudflareaccess.com
    # - CLOUDFLARE_AUDIENCE_TAG=your-audience-tag
    # - CLOUDFLARE_ENABLED=true

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
