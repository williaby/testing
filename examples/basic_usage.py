"""Basic example of using Cloudflare authentication middleware.

This example shows how to set up a simple FastAPI application with
Cloudflare Access authentication.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from src.cloudflare_auth import CloudflareUser, setup_cloudflare_auth
from src.cloudflare_auth.middleware import get_current_user, get_current_user_optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events."""
    # Startup
    logging.info("Starting application...")
    yield
    # Shutdown
    logging.info("Shutting down application...")


# Create FastAPI app
app = FastAPI(
    title="Cloudflare Auth Example",
    description="Example FastAPI application with Cloudflare Access authentication",
    version="1.0.0",
    lifespan=lifespan,
)

# Setup Cloudflare authentication
# Excluded paths don't require authentication
setup_cloudflare_auth(
    app,
    excluded_paths=[
        "/",
        "/health",
        "/public",
    ],
    require_auth=True,  # Require authentication for non-excluded paths
)


# Public endpoints (no authentication required)
@app.get("/")
async def root():
    """Public endpoint - no authentication required."""
    return {
        "message": "Welcome to the Cloudflare Auth example",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Health check endpoint - no authentication required."""
    return {"status": "healthy"}


@app.get("/public")
async def public_endpoint():
    """Public endpoint - no authentication required."""
    return {"message": "This endpoint is public"}


# Protected endpoints (authentication required)
@app.get("/protected")
async def protected_endpoint(request: Request):
    """Protected endpoint - authentication required.

    Access user via request.state.user
    """
    user: CloudflareUser = request.state.user
    return {
        "message": "This is a protected endpoint",
        "user": {
            "email": user.email,
            "user_id": user.user_id,
            "domain": user.email_domain,
        },
    }


@app.get("/me")
async def get_current_user_info(user: CloudflareUser = Depends(get_current_user)):
    """Get current user information using dependency injection."""
    return {
        "email": user.email,
        "user_id": user.user_id,
        "email_domain": user.email_domain,
        "authenticated_at": user.authenticated_at.isoformat(),
    }


@app.get("/optional-auth")
async def optional_auth_endpoint(
    user: CloudflareUser | None = Depends(get_current_user_optional)
):
    """Endpoint with optional authentication.

    Returns different content based on whether user is authenticated.
    """
    if user:
        return {
            "message": f"Hello, {user.email}!",
            "authenticated": True,
        }
    else:
        return {
            "message": "Hello, anonymous user!",
            "authenticated": False,
        }


@app.get("/admin")
async def admin_endpoint(user: CloudflareUser = Depends(get_current_user)):
    """Admin endpoint - only accessible to specific email domains."""
    # Example: Only allow users from specific domains
    allowed_domains = ["example.com", "admin.example.com"]

    if user.email_domain not in allowed_domains:
        return JSONResponse(
            status_code=403,
            content={"detail": "Access forbidden - admin domain required"},
        )

    return {
        "message": "Welcome to the admin panel",
        "user": user.email,
    }


@app.get("/user-details")
async def get_user_details(user: CloudflareUser = Depends(get_current_user)):
    """Get detailed user information including JWT claims."""
    return {
        "user": {
            "email": user.email,
            "user_id": user.user_id,
            "email_domain": user.email_domain,
            "email_username": user.email_username,
            "authenticated_at": user.authenticated_at.isoformat(),
        },
        "jwt_claims": {
            "issuer": user.claims.iss,
            "audience": user.claims.get_audience_list(),
            "issued_at": user.claims.issued_at.isoformat(),
            "expires_at": user.claims.expires_at.isoformat(),
            "is_expired": user.claims.is_expired,
        },
    }


if __name__ == "__main__":
    import uvicorn

    # Run the application
    # Make sure to set environment variables:
    # - CLOUDFLARE_TEAM_DOMAIN=your-team.cloudflareaccess.com
    # - CLOUDFLARE_AUDIENCE_TAG=your-audience-tag
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
