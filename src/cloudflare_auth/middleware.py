"""Cloudflare Access authentication middleware for FastAPI.

This module provides middleware that authenticates requests using Cloudflare
Access JWT tokens. It extracts and validates authentication headers, creates
user objects, and makes them available to request handlers.

The middleware integrates with Cloudflare Access tunnel authentication,
allowing applications to trust user identity verified by Cloudflare.

Key Features:
    - Automatic JWT token validation
    - User object injection into request state
    - Configurable path exclusions
    - Comprehensive error handling and logging
    - Development mode bypass support

Architecture:
    The middleware follows the ASGI middleware pattern, processing each
    request before it reaches the application handlers. It validates
    Cloudflare headers, verifies JWT tokens, and attaches user information
    to the request.

Dependencies:
    - fastapi: For Request/Response handling
    - starlette: For BaseHTTPMiddleware
    - src.cloudflare_auth.validators: For JWT validation
    - src.cloudflare_auth.models: For user models
    - src.config.settings: For configuration

Called by:
    - FastAPI middleware stack during request processing
    - Application initialization (setup_cloudflare_auth)

Example:
    from fastapi import FastAPI, Request
    from src.cloudflare_auth import setup_cloudflare_auth

    app = FastAPI()
    setup_cloudflare_auth(app)

    @app.get("/protected")
    async def protected_route(request: Request):
        user = request.state.user  # CloudflareUser object
        return {"email": user.email}

Complexity: O(1) for token validation with cached keys
"""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.cloudflare_auth.models import CloudflareUser
from src.cloudflare_auth.validators import CloudflareJWTValidator
from src.config.settings import CloudflareSettings, get_cloudflare_settings


logger = logging.getLogger(__name__)


class CloudflareAuthMiddleware(BaseHTTPMiddleware):
    """Middleware for Cloudflare Access authentication.

    This middleware authenticates requests using JWT tokens from
    Cloudflare Access headers. It validates tokens, extracts user
    information, and makes it available via request.state.user.

    Attributes:
        validator: JWT token validator instance
        settings: Cloudflare configuration settings
        excluded_paths: Paths that bypass authentication
        require_auth: Whether to enforce authentication (True) or just parse it (False)

    Example:
        # In your FastAPI app
        app.add_middleware(
            CloudflareAuthMiddleware,
            excluded_paths=["/health", "/docs"],
            require_auth=True,
        )
    """

    def __init__(
        self,
        app: Any,
        settings: CloudflareSettings | None = None,
        validator: CloudflareJWTValidator | None = None,
        excluded_paths: list[str] | None = None,
        require_auth: bool = True,
    ) -> None:
        """Initialize Cloudflare authentication middleware.

        Args:
            app: The ASGI application
            settings: Optional CloudflareSettings instance
            validator: Optional CloudflareJWTValidator instance
            excluded_paths: List of paths to exclude from authentication
            require_auth: Whether to require authentication (vs. optional)
        """
        super().__init__(app)
        self.settings = settings or get_cloudflare_settings()
        self.validator = validator or CloudflareJWTValidator(self.settings)
        self.excluded_paths = excluded_paths or []
        self.require_auth = require_auth

        # Log configuration
        logger.info(
            "Cloudflare auth middleware initialized (enabled=%s, require_auth=%s)",
            self.settings.cloudflare_enabled,
            self.require_auth,
        )

    def _is_path_excluded(self, path: str) -> bool:
        """Check if a path should bypass authentication.

        Args:
            path: Request path to check

        Returns:
            True if path is in excluded list
        """
        # Exact match or prefix match
        return any(
            path == excluded or path.startswith(excluded.rstrip("/") + "/")
            for excluded in self.excluded_paths
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request with Cloudflare authentication.

        This method implements the core middleware functionality:
        1. Check if path is excluded from authentication
        2. Extract JWT token from headers
        3. Validate token and create user object
        4. Attach user to request.state
        5. Process request through application

        Args:
            request: The incoming request
            call_next: The next middleware/endpoint in the chain

        Returns:
            Response from the application

        Raises:
            HTTPException: If authentication fails and is required

        Time Complexity: O(1) for token validation with cached keys
        Space Complexity: O(1) for user object creation

        Called by:
            - FastAPI middleware stack during request processing
        """
        # Check if this path should skip authentication
        if self._is_path_excluded(request.url.path):
            logger.debug("Path excluded from auth: %s", request.url.path)
            return await call_next(request)

        # Skip authentication if disabled (development mode)
        if not self.settings.cloudflare_enabled:
            logger.debug("Cloudflare authentication disabled")
            # Set a mock user for development
            if not self.require_auth:
                request.state.user = None
            return await call_next(request)

        # Extract and validate authentication
        try:
            user = await self._authenticate_request(request)
            request.state.user = user

            logger.debug(
                "Authenticated request for user: %s (path: %s)",
                user.email if user else "none",
                request.url.path,
            )

        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(
                "Unexpected error during authentication: %s",
                str(e),
                exc_info=True,
            )
            if self.require_auth:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Authentication service error",
                ) from e
            else:
                # Non-required auth: continue without user
                request.state.user = None

        # Process the request
        return await call_next(request)

    async def _authenticate_request(self, request: Request) -> CloudflareUser | None:
        """Authenticate request using Cloudflare headers.

        This method extracts the JWT token from request headers,
        validates it, and creates a CloudflareUser object.

        Args:
            request: The incoming request

        Returns:
            CloudflareUser object if authentication succeeds, None if optional

        Raises:
            HTTPException: If authentication fails and is required

        Called by:
            - dispatch(): During request processing
        """
        # Extract JWT token from header
        jwt_token = request.headers.get(self.settings.jwt_header_name)

        if not jwt_token:
            if self.require_auth:
                if self.settings.log_auth_failures:
                    logger.warning(
                        "Missing Cloudflare JWT header: %s (path: %s, ip: %s)",
                        self.settings.jwt_header_name,
                        request.url.path,
                        self._get_client_ip(request),
                    )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                # Auth not required, return None
                return None

        # Validate the JWT token
        try:
            claims = self.validator.validate_token(jwt_token)
            user = CloudflareUser.from_jwt_claims(claims)

            # Additional email header validation (optional security check)
            email_header = request.headers.get(self.settings.email_header_name)
            if email_header and email_header != user.email:
                logger.warning(
                    "Email mismatch: JWT=%s, Header=%s",
                    user.email,
                    email_header,
                )
                if self.require_auth:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Email verification failed",
                    )

            logger.info(
                "User authenticated successfully: %s (path: %s)",
                user.email,
                request.url.path,
            )

            return user

        except ValueError as e:
            if self.settings.log_auth_failures:
                logger.warning(
                    "JWT validation failed: %s (path: %s, ip: %s)",
                    str(e),
                    request.url.path,
                    self._get_client_ip(request),
                )

            if self.require_auth:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid authentication token: {str(e)}",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e
            else:
                return None

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request.

        Args:
            request: The incoming request

        Returns:
            Client IP address string
        """
        # Cloudflare specific headers
        cf_connecting_ip = request.headers.get("CF-Connecting-IP")
        if cf_connecting_ip:
            return cf_connecting_ip

        # Standard forwarding headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct client IP
        return request.client.host if request.client else "unknown"


def setup_cloudflare_auth(
    app: Any,
    excluded_paths: list[str] | None = None,
    require_auth: bool = True,
    settings: CloudflareSettings | None = None,
) -> None:
    """Configure Cloudflare authentication for FastAPI application.

    This is a convenience function to add CloudflareAuthMiddleware
    to your FastAPI application with sensible defaults.

    Args:
        app: The FastAPI application instance
        excluded_paths: Optional list of paths to exclude from auth
        require_auth: Whether authentication is required (vs. optional)
        settings: Optional CloudflareSettings instance

    Example:
        from fastapi import FastAPI
        from src.cloudflare_auth import setup_cloudflare_auth

        app = FastAPI()

        # Setup with default settings
        setup_cloudflare_auth(app)

        # Or with custom configuration
        setup_cloudflare_auth(
            app,
            excluded_paths=["/health", "/metrics", "/docs", "/openapi.json"],
            require_auth=True,
        )

    Called by:
        - Application initialization code
        - main.py or app factory functions
    """
    settings = settings or get_cloudflare_settings()

    # Default excluded paths for common endpoints
    default_excluded = [
        "/health",
        "/healthz",
        "/ready",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
    ]

    # Merge with user-provided excluded paths
    all_excluded = list(set(default_excluded + (excluded_paths or [])))

    # Add the middleware
    app.add_middleware(
        CloudflareAuthMiddleware,
        settings=settings,
        excluded_paths=all_excluded,
        require_auth=require_auth,
    )

    logger.info(
        "Cloudflare authentication configured (team=%s, excluded_paths=%d)",
        settings.cloudflare_team_domain,
        len(all_excluded),
    )


def get_current_user(request: Request) -> CloudflareUser:
    """Dependency to get the current authenticated user.

    This function can be used as a FastAPI dependency to access
    the authenticated user in route handlers.

    Args:
        request: The FastAPI request object

    Returns:
        CloudflareUser object

    Raises:
        HTTPException: If user is not authenticated

    Example:
        from fastapi import Depends
        from src.cloudflare_auth import get_current_user, CloudflareUser

        @app.get("/me")
        async def get_me(user: CloudflareUser = Depends(get_current_user)):
            return {"email": user.email, "user_id": user.user_id}

    Called by:
        - FastAPI dependency injection system
        - Route handlers requiring authenticated users
    """
    user = getattr(request.state, "user", None)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_current_user_optional(request: Request) -> CloudflareUser | None:
    """Dependency to optionally get the current user.

    Similar to get_current_user but returns None instead of
    raising an exception if the user is not authenticated.

    Args:
        request: The FastAPI request object

    Returns:
        CloudflareUser object or None if not authenticated

    Example:
        from fastapi import Depends
        from src.cloudflare_auth import get_current_user_optional, CloudflareUser

        @app.get("/info")
        async def get_info(user: CloudflareUser | None = Depends(get_current_user_optional)):
            if user:
                return {"message": f"Hello {user.email}"}
            return {"message": "Hello anonymous user"}
    """
    return getattr(request.state, "user", None)
