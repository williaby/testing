"""Advanced example with custom security middleware and role-based access.

This example demonstrates:
- Combining Cloudflare auth with custom security headers
- Role-based access control
- Custom authentication logic
- Email domain restrictions
"""

import logging
from contextlib import asynccontextmanager
from functools import wraps
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from src.cloudflare_auth import CloudflareUser, setup_cloudflare_auth
from src.cloudflare_auth.middleware import get_current_user

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Custom role-based access control
def require_email_domain(*allowed_domains: str) -> Callable:
    """Decorator to require specific email domains.

    Args:
        *allowed_domains: Email domains that are allowed

    Example:
        @app.get("/admin")
        @require_email_domain("example.com", "admin.example.com")
        async def admin_route(user: CloudflareUser = Depends(get_current_user)):
            return {"message": "Admin access granted"}
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user from kwargs (injected by Depends)
            user: CloudflareUser | None = kwargs.get("user")

            # If no user in kwargs, try to get from request
            if not user:
                request: Request | None = kwargs.get("request")
                if request:
                    user = getattr(request.state, "user", None)

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            if user.email_domain not in allowed_domains:
                logger.warning(
                    "Access denied for user %s (domain: %s, required: %s)",
                    user.email,
                    user.email_domain,
                    allowed_domains,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied - allowed domains: {', '.join(allowed_domains)}",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_specific_users(*allowed_emails: str) -> Callable:
    """Decorator to require specific user emails.

    Args:
        *allowed_emails: Email addresses that are allowed

    Example:
        @app.get("/super-admin")
        @require_specific_users("admin@example.com", "superuser@example.com")
        async def super_admin_route(user: CloudflareUser = Depends(get_current_user)):
            return {"message": "Super admin access granted"}
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user: CloudflareUser | None = kwargs.get("user")

            if not user:
                request: Request | None = kwargs.get("request")
                if request:
                    user = getattr(request.state, "user", None)

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            if user.email not in allowed_emails:
                logger.warning(
                    "Access denied for user %s (required: %s)",
                    user.email,
                    allowed_emails,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied - insufficient permissions",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager."""
    logger.info("Starting advanced example application...")
    yield
    logger.info("Shutting down application...")


# Create FastAPI app
app = FastAPI(
    title="Advanced Cloudflare Auth Example",
    description="Advanced example with role-based access control",
    version="1.0.0",
    lifespan=lifespan,
)

# Setup Cloudflare authentication
setup_cloudflare_auth(
    app,
    excluded_paths=["/", "/health", "/public"],
    require_auth=True,
)


@app.get("/")
async def root():
    """Public root endpoint."""
    return {
        "message": "Advanced Cloudflare Auth Example",
        "endpoints": {
            "public": "/public",
            "authenticated": "/protected",
            "admin": "/admin (requires example.com domain)",
            "super_admin": "/super-admin (requires specific users)",
        },
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/protected")
async def protected(user: CloudflareUser = Depends(get_current_user)):
    """Basic protected endpoint."""
    return {
        "message": "Protected endpoint",
        "user": user.email,
    }


@app.get("/admin")
@require_email_domain("example.com", "admin.example.com")
async def admin_panel(user: CloudflareUser = Depends(get_current_user)):
    """Admin panel - requires specific email domains."""
    return {
        "message": "Welcome to the admin panel",
        "user": user.email,
        "domain": user.email_domain,
        "access_level": "admin",
    }


@app.get("/super-admin")
@require_specific_users("admin@example.com", "superuser@example.com")
async def super_admin_panel(user: CloudflareUser = Depends(get_current_user)):
    """Super admin panel - requires specific user emails."""
    return {
        "message": "Welcome to the super admin panel",
        "user": user.email,
        "access_level": "super_admin",
    }


@app.post("/admin/users")
@require_email_domain("example.com")
async def create_user(
    request: Request,
    user: CloudflareUser = Depends(get_current_user),
):
    """Create a new user - admin only."""
    body = await request.json()

    logger.info(
        "User creation requested by %s: %s",
        user.email,
        body,
    )

    return {
        "message": "User created successfully",
        "created_by": user.email,
        "data": body,
    }


@app.get("/user/profile")
async def get_user_profile(user: CloudflareUser = Depends(get_current_user)):
    """Get detailed user profile."""
    return {
        "profile": {
            "email": user.email,
            "user_id": user.user_id,
            "domain": user.email_domain,
            "username": user.email_username,
        },
        "authentication": {
            "authenticated_at": user.authenticated_at.isoformat(),
            "issuer": user.claims.iss,
            "expires_at": user.claims.expires_at.isoformat(),
        },
        "permissions": {
            "is_admin": user.has_email_domain("example.com"),
            "is_super_admin": user.email in ["admin@example.com"],
        },
    }


# Custom exception handler for better error messages
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom exception handler for HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "status_code": exc.status_code,
                "message": exc.detail,
                "path": str(request.url.path),
            }
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
