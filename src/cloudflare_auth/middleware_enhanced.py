"""Enhanced Cloudflare Access authentication middleware with JWT, whitelist, and sessions.

This module provides comprehensive FastAPI middleware that combines:
- JWT token validation for security
- Email whitelist with domain and tier support
- Session management with cookies
- Development mode for local testing

Key Features:
    - Secure JWT validation using Cloudflare certificates
    - Email whitelist with @domain.com pattern support
    - User tiers (admin/full/limited) for access control
    - In-memory session management with cookies
    - Development mode with mock users
    - Comprehensive logging and error handling

Dependencies:
    - fastapi: For Request/Response handling
    - starlette: For middleware base classes
    - src.cloudflare_auth.validators: For JWT validation
    - src.cloudflare_auth.whitelist: For email validation
    - src.cloudflare_auth.sessions: For session management

Called by:
    - FastAPI middleware stack during request processing

Example:
    from fastapi import FastAPI
    from src.cloudflare_auth import setup_cloudflare_auth_enhanced

    app = FastAPI()
    setup_cloudflare_auth_enhanced(
        app,
        whitelist=["user@example.com", "@company.com"],
        admin_emails=["admin@company.com"]
    )
"""

from collections.abc import Callable
import logging
from typing import Any

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from src.cloudflare_auth.csrf import CSRFProtection
from src.cloudflare_auth.models import CloudflareUser
from src.cloudflare_auth.rate_limiter import InMemoryRateLimiter
from src.cloudflare_auth.sessions import SimpleSessionManager
from src.cloudflare_auth.utils import get_client_ip, sanitize_email, sanitize_ip, sanitize_path
from src.cloudflare_auth.validators import CloudflareJWTValidator
from src.cloudflare_auth.whitelist import EmailWhitelistValidator, UserTier
from src.config.settings import CloudflareSettings, get_cloudflare_settings


logger = logging.getLogger(__name__)


class CloudflareAuthMiddlewareEnhanced(BaseHTTPMiddleware):
    """Enhanced Cloudflare Access middleware with JWT, whitelist, and sessions.

    This middleware provides complete authentication with:
    - JWT token validation (secure)
    - Email whitelist authorization
    - User tier assignment
    - Session management
    - Development mode support

    Example:
        middleware = CloudflareAuthMiddlewareEnhanced(
            app=app,
            whitelist_validator=validator,
            session_manager=session_manager,
            excluded_paths=["/health", "/docs"],
            enable_sessions=True
        )
    """

    def __init__(
        self,
        app: Any,
        settings: CloudflareSettings | None = None,
        validator: CloudflareJWTValidator | None = None,
        whitelist_validator: EmailWhitelistValidator | None = None,
        session_manager: SimpleSessionManager | None = None,
        excluded_paths: list[str] | None = None,
        enable_sessions: bool = True,
        require_auth: bool = True,
        enable_rate_limiting: bool = True,
        rate_limit_attempts: int = 5,
        rate_limit_window: int = 60,
    ) -> None:
        """Initialize enhanced authentication middleware.

        Args:
            app: ASGI application
            settings: Cloudflare configuration settings
            validator: JWT token validator
            whitelist_validator: Email whitelist validator (required)
            session_manager: Session manager instance
            excluded_paths: Paths to exclude from authentication
            enable_sessions: Whether to use session cookies
            require_auth: Whether authentication is required
            enable_rate_limiting: Whether to enable rate limiting (default: True)
            rate_limit_attempts: Max authentication attempts per window (default: 5)
            rate_limit_window: Rate limit window in seconds (default: 60)
        """
        super().__init__(app)
        self.settings = settings or get_cloudflare_settings()
        self.jwt_validator = validator or CloudflareJWTValidator(self.settings)
        self.whitelist_validator = whitelist_validator
        self.session_manager = session_manager or SimpleSessionManager()
        self.excluded_paths = excluded_paths or []
        self.enable_sessions = enable_sessions
        self.require_auth = require_auth

        # Rate limiting
        self.enable_rate_limiting = enable_rate_limiting
        if enable_rate_limiting:
            self.rate_limiter = InMemoryRateLimiter(
                max_attempts=rate_limit_attempts,
                window_seconds=rate_limit_window,
            )
        else:
            self.rate_limiter = None

        # CSRF protection for sessions
        if enable_sessions:
            self.csrf_protection = CSRFProtection()
        else:
            self.csrf_protection = None

        # Validate configuration
        if self.settings.cloudflare_enabled and require_auth:
            if not whitelist_validator:
                logger.warning(
                    "No whitelist validator provided - all authenticated users will be allowed"
                )

        logger.info(
            "Initialized enhanced Cloudflare auth middleware "
            "(JWT enabled=%s, sessions=%s, whitelist=%s, rate_limiting=%s)",
            self.settings.cloudflare_enabled,
            self.enable_sessions,
            whitelist_validator is not None,
            self.enable_rate_limiting,
        )

    def _is_path_excluded(self, path: str) -> bool:
        """Check if a path should bypass authentication.

        Args:
            path: Request path to check

        Returns:
            True if path is excluded from auth
        """
        return any(
            path == excluded or path.startswith(excluded.rstrip("/") + "/")
            for excluded in self.excluded_paths
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request with enhanced authentication.

        Authentication flow:
        1. Check if path is excluded
        2. Check for existing valid session
        3. Validate JWT token from Cloudflare
        4. Check email whitelist
        5. Determine user tier and privileges
        6. Create/update session
        7. Inject user into request.state

        Args:
            request: Incoming request
            call_next: Next middleware/endpoint

        Returns:
            Response from application
        """
        # Skip authentication for excluded paths
        if self._is_path_excluded(request.url.path):
            logger.debug("Path excluded from auth: %s", request.url.path)
            return await call_next(request)

        # Handle development mode (no Cloudflare)
        if not self.settings.cloudflare_enabled:
            logger.debug("Cloudflare authentication disabled (dev mode)")
            if not self.require_auth:
                request.state.user = None
            return await call_next(request)

        # Authenticate the request
        try:
            user = await self._authenticate_request(request)
            request.state.user = user

            response = await call_next(request)

            # Set session cookie if needed
            if (
                self.enable_sessions
                and user
                and user.session_id
                and user.session_id != request.cookies.get("session_id")
            ):
                self._set_session_cookie(response, user.session_id)

            return response

        except HTTPException:
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
                request.state.user = None
                return await call_next(request)

    async def _authenticate_request(self, request: Request) -> CloudflareUser | None:
        """Authenticate request using JWT and whitelist.

        Args:
            request: Incoming request

        Returns:
            CloudflareUser object if authenticated, None if optional

        Raises:
            HTTPException: If authentication fails and is required
        """
        # Check rate limit
        if self.enable_rate_limiting and self.rate_limiter:
            client_ip = get_client_ip(request)
            if not self.rate_limiter.is_allowed(client_ip):
                retry_after = self.rate_limiter.get_retry_after(client_ip)
                logger.warning(
                    "Rate limit exceeded for IP: %s (path: %s)",
                    sanitize_ip(client_ip),
                    sanitize_path(request.url.path),
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many authentication attempts. Please try again later.",
                    headers={"Retry-After": str(retry_after)},
                )

        # Check for existing session first
        if self.enable_sessions:
            session_id = request.cookies.get("session_id")
            if session_id:
                session = self.session_manager.get_session(session_id)
                if session:
                    # Recreate user from session
                    user = self._user_from_session(session, session_id)
                    logger.debug("Authenticated from session: %s", user.email)
                    return user

        # Extract JWT token
        jwt_token = request.headers.get(self.settings.jwt_header_name)

        if not jwt_token:
            if self.require_auth:
                if self.settings.log_auth_failures:
                    logger.warning(
                        "Missing JWT header: %s (path: %s, ip: %s)",
                        self.settings.jwt_header_name,
                        sanitize_path(request.url.path),
                        sanitize_ip(get_client_ip(request)),
                    )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        # Security: Validate JWT token size (prevent DoS)
        if len(jwt_token) > 8192:  # 8KB limit
            logger.warning(
                "JWT token too large: %d bytes (path: %s, ip: %s)",
                len(jwt_token),
                request.url.path,
                self._get_client_ip(request),
            )
            if self.require_auth:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="JWT token too large",
                )
            return None

        # Validate JWT token
        try:
            claims = self.jwt_validator.validate_token(jwt_token)
        except ValueError as e:
            # Record failed authentication attempt for rate limiting
            if self.enable_rate_limiting and self.rate_limiter:
                client_ip = get_client_ip(request)
                self.rate_limiter.record_attempt(client_ip)

            if self.settings.log_auth_failures:
                logger.warning(
                    "JWT validation failed: %s (path: %s, ip: %s)",
                    str(e),
                    sanitize_path(request.url.path),
                    sanitize_ip(get_client_ip(request)),
                )

            if self.require_auth:
                # Don't leak error details to potential attackers
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e
            return None

        # Check whitelist if configured
        if self.whitelist_validator:
            if not self.whitelist_validator.is_authorized(claims.email):
                logger.warning(
                    "Unauthorized email attempted access: %s",
                    sanitize_email(claims.email),
                )
                if self.require_auth:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Email {claims.email} not authorized",
                    )
                return None

            # Get user tier
            try:
                user_tier = self.whitelist_validator.get_user_tier(claims.email)
            except ValueError:
                user_tier = UserTier.LIMITED
        else:
            # No whitelist - default to full access
            user_tier = UserTier.FULL

        # Create or update session
        session_id = None
        if self.enable_sessions:
            session_id = self.session_manager.create_session(
                email=claims.email,
                is_admin=user_tier.has_admin_privileges,
                user_tier=user_tier.value,
                cf_context={
                    "cf_ray": request.headers.get("cf-ray"),
                    "cf_country": request.headers.get("cf-ipcountry"),
                },
            )

        # Create user object
        user = CloudflareUser.from_jwt_claims(
            claims=claims,
            user_tier=user_tier,
            is_admin=user_tier.has_admin_privileges,
            session_id=session_id,
        )

        logger.info(
            "User authenticated: %s (tier: %s, admin: %s)",
            sanitize_email(user.email),
            user_tier.value,
            user.is_admin,
        )

        return user

    def _user_from_session(
        self,
        session: dict[str, Any],
        session_id: str
    ) -> CloudflareUser:
        """Recreate CloudflareUser from session data.

        Args:
            session: Session data dictionary
            session_id: Session identifier

        Returns:
            CloudflareUser instance
        """
        from src.cloudflare_auth.models import CloudflareJWTClaims

        # Create minimal claims for session-based auth
        claims = CloudflareJWTClaims(
            email=session["email"],
            iss=self.settings.issuer,
            aud=[self.settings.cloudflare_audience_tag],
            sub=session.get("email", ""),
            iat=int(session["created_at"].timestamp()),
            exp=int(session["last_accessed"].timestamp()) + self.session_manager.session_timeout,
        )

        tier = UserTier.from_string(session.get("user_tier", "limited"))

        return CloudflareUser.from_jwt_claims(
            claims=claims,
            user_tier=tier,
            is_admin=session.get("is_admin", False),
            session_id=session_id,
        )

    def _set_session_cookie(self, response: Response, session_id: str) -> None:
        """Set session cookie and CSRF token in response.

        Uses security settings from configuration for proper cookie attributes.

        Args:
            response: Response to modify
            session_id: Session ID to set
        """
        # Prepare cookie kwargs from settings
        cookie_kwargs = {
            "max_age": self.session_manager.session_timeout,
            "path": self.settings.cookie_path,
            "secure": self.settings.cookie_secure,
            "samesite": self.settings.cookie_samesite,
        }

        # Add domain if configured
        if self.settings.cookie_domain:
            cookie_kwargs["domain"] = self.settings.cookie_domain

        # Set session cookie (httponly for security)
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            **cookie_kwargs,
        )

        # Set CSRF token cookie (NOT httponly, needs to be readable by JS)
        if self.csrf_protection:
            csrf_token = self.csrf_protection.generate_token(session_id)
            response.set_cookie(
                key="csrf_token",
                value=csrf_token,
                httponly=False,  # Must be readable by JavaScript
                **cookie_kwargs,
            )


def setup_cloudflare_auth_enhanced(
    app: Any,
    whitelist: list[str] | None = None,
    admin_emails: list[str] | None = None,
    full_users: list[str] | None = None,
    limited_users: list[str] | None = None,
    excluded_paths: list[str] | None = None,
    enable_sessions: bool = True,
    require_auth: bool = True,
    session_timeout: int = 3600,
    settings: CloudflareSettings | None = None,
) -> CloudflareAuthMiddlewareEnhanced:
    """Setup enhanced Cloudflare authentication with all features.

    This is the recommended setup function that provides:
    - JWT validation for security
    - Email whitelist authorization
    - User tier management
    - Session support
    - Development mode

    Args:
        app: FastAPI application
        whitelist: List of allowed emails/domains (e.g., ["user@example.com", "@company.com"])
        admin_emails: List of admin emails
        full_users: List of full-tier users
        limited_users: List of limited-tier users
        excluded_paths: Paths to exclude from auth
        enable_sessions: Whether to use session cookies
        require_auth: Whether authentication is required
        session_timeout: Session timeout in seconds
        settings: Optional CloudflareSettings instance

    Returns:
        Configured middleware instance

    Example:
        app = FastAPI()
        setup_cloudflare_auth_enhanced(
            app,
            whitelist=["user@example.com", "@company.com"],
            admin_emails=["admin@company.com"],
            full_users=["@company.com"],
            excluded_paths=["/health", "/docs"],
            enable_sessions=True
        )
    """
    settings = settings or get_cloudflare_settings()

    # Create whitelist validator if whitelist provided
    whitelist_validator = None
    if whitelist:
        whitelist_validator = EmailWhitelistValidator(
            whitelist=whitelist,
            admin_emails=admin_emails or [],
            full_users=full_users or [],
            limited_users=limited_users or [],
        )

        # Log whitelist stats
        stats = whitelist_validator.get_whitelist_stats()
        logger.info(
            "Whitelist configured: %d entries, %d domains, %d admins",
            stats["total_entries"],
            len(stats["domains"]),
            stats["admin_emails"],
        )

        # Check for warnings
        warnings = whitelist_validator.validate_whitelist_config()
        for warning in warnings:
            logger.warning("Whitelist config: %s", warning)

    # Create session manager
    session_manager = None
    if enable_sessions:
        session_manager = SimpleSessionManager(session_timeout=session_timeout)

    # Create JWT validator
    jwt_validator = CloudflareJWTValidator(settings)

    # Default excluded paths
    default_excluded = [
        "/health",
        "/healthz",
        "/ready",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
    ]

    all_excluded = list(set(default_excluded + (excluded_paths or [])))

    # Add middleware
    app.add_middleware(
        CloudflareAuthMiddlewareEnhanced,
        settings=settings,
        validator=jwt_validator,
        whitelist_validator=whitelist_validator,
        session_manager=session_manager,
        excluded_paths=all_excluded,
        enable_sessions=enable_sessions,
        require_auth=require_auth,
    )

    logger.info(
        "Enhanced Cloudflare authentication configured "
        "(whitelist=%s, sessions=%s, excluded_paths=%d)",
        whitelist_validator is not None,
        enable_sessions,
        len(all_excluded),
    )

    return None  # Middleware is added directly to app


# FastAPI dependencies
def get_current_user(request: Request) -> CloudflareUser:
    """FastAPI dependency to get current authenticated user.

    Args:
        request: FastAPI request

    Returns:
        CloudflareUser object

    Raises:
        HTTPException: If user is not authenticated

    Example:
        @app.get("/me")
        async def get_me(user: CloudflareUser = Depends(get_current_user)):
            return {"email": user.email}
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
    """FastAPI dependency for optional authentication.

    Args:
        request: FastAPI request

    Returns:
        CloudflareUser or None

    Example:
        @app.get("/info")
        async def info(user: CloudflareUser | None = Depends(get_current_user_optional)):
            if user:
                return {"message": f"Hello {user.email}"}
            return {"message": "Hello anonymous"}
    """
    return getattr(request.state, "user", None)


def require_admin(request: Request) -> CloudflareUser:
    """FastAPI dependency requiring admin privileges.

    Args:
        request: FastAPI request

    Returns:
        CloudflareUser object

    Raises:
        HTTPException: If not authenticated or not admin

    Example:
        @app.get("/admin")
        async def admin_panel(user: CloudflareUser = Depends(require_admin)):
            return {"message": "Admin panel"}
    """
    user = get_current_user(request)

    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    return user


def require_tier(minimum_tier: UserTier) -> Callable:
    """Create a dependency that requires a minimum user tier.

    Args:
        minimum_tier: Minimum required tier

    Returns:
        Dependency function

    Example:
        require_full = require_tier(UserTier.FULL)

        @app.get("/premium")
        async def premium(user: CloudflareUser = Depends(require_full)):
            return {"message": "Premium content"}
    """
    def dependency(request: Request) -> CloudflareUser:
        user = get_current_user(request)

        tier_order = {
            UserTier.LIMITED: 0,
            UserTier.FULL: 1,
            UserTier.ADMIN: 2,
        }

        if tier_order[user.user_tier] < tier_order[minimum_tier]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Minimum tier {minimum_tier.value} required",
            )

        return user

    return dependency
