"""Security helper utilities and middleware.

This module provides additional security enhancements including:
- Security headers middleware
- Session cleanup background tasks
- Rate limiting helpers
- Audit logging

Dependencies:
    - fastapi: For middleware
    - starlette: For middleware base

Called by:
    - Application initialization
    - Security-conscious applications
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.cloudflare_auth.sessions import SimpleSessionManager


logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses.

    This middleware adds essential security headers to protect against
    common web vulnerabilities.

    Headers added:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 0 (disabled, rely on CSP)
    - Content-Security-Policy: Configurable
    - Referrer-Policy: strict-origin-when-cross-origin
    - Permissions-Policy: Restrictive permissions
    - Strict-Transport-Security: HSTS (production only)

    Example:
        app.add_middleware(SecurityHeadersMiddleware)
    """

    def __init__(
        self,
        app: Any,
        csp_policy: str | None = None,
        enable_hsts: bool = True,
    ) -> None:
        """Initialize security headers middleware.

        Args:
            app: ASGI application
            csp_policy: Custom Content Security Policy
            enable_hsts: Enable HSTS headers
        """
        super().__init__(app)
        self.csp_policy = csp_policy or self._default_csp_policy()
        self.enable_hsts = enable_hsts

    def _default_csp_policy(self) -> str:
        """Generate default Content Security Policy.

        Returns:
            CSP policy string
        """
        return (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Add security headers to response.

        Args:
            request: Incoming request
            call_next: Next middleware/endpoint

        Returns:
            Response with security headers
        """
        response = await call_next(request)

        # Add security headers
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "0",
            "Content-Security-Policy": self.csp_policy,
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": (
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=()"
            ),
        }

        # Add HSTS in production
        if self.enable_hsts:
            headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value

        return response


def create_session_cleanup_task(
    session_manager: SimpleSessionManager,
    cleanup_interval: int = 300,
) -> asyncio.Task:
    """Create background task for session cleanup.

    This function creates an asyncio task that periodically cleans up
    expired sessions to prevent memory leaks.

    Args:
        session_manager: Session manager to clean
        cleanup_interval: Cleanup interval in seconds (default: 5 minutes)

    Returns:
        Asyncio task handle

    Example:
        @app.on_event("startup")
        async def startup():
            task = create_session_cleanup_task(session_manager)
            # Store task to prevent garbage collection
            app.state.cleanup_task = task

        @app.on_event("shutdown")
        async def shutdown():
            app.state.cleanup_task.cancel()
    """
    async def cleanup_loop():
        """Background loop for session cleanup."""
        logger.info(
            "Session cleanup task started (interval: %ds)",
            cleanup_interval
        )
        try:
            while True:
                await asyncio.sleep(cleanup_interval)
                count = session_manager.cleanup_expired_sessions()
                if count > 0:
                    logger.info("Cleaned up %d expired sessions", count)
        except asyncio.CancelledError:
            logger.info("Session cleanup task cancelled")
            raise
        except Exception as e:
            logger.error("Session cleanup error: %s", e, exc_info=True)

    return asyncio.create_task(cleanup_loop())


class AuditLogger:
    """Audit logger for security-sensitive operations.

    This class provides structured logging for admin actions,
    authentication events, and other security-critical operations.

    Example:
        audit = AuditLogger()

        audit.log_admin_action(
            admin_email="admin@company.com",
            action="create_user",
            target="newuser@company.com",
            result="success"
        )

        audit.log_auth_event(
            event_type="login_success",
            user_email="user@company.com",
            ip_address="192.168.1.1"
        )
    """

    def __init__(self, logger_name: str = "audit") -> None:
        """Initialize audit logger.

        Args:
            logger_name: Name for the audit logger
        """
        self.logger = logging.getLogger(logger_name)

    def log_admin_action(
        self,
        admin_email: str,
        action: str,
        target: str | None = None,
        result: str = "success",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log administrative action.

        Args:
            admin_email: Email of admin performing action
            action: Action performed (e.g., "create_user", "delete_data")
            target: Target of action (e.g., affected user email)
            result: Result of action ("success", "failure", "denied")
            details: Additional details dictionary
        """
        self.logger.info(
            "ADMIN_ACTION: %s performed %s on %s (result: %s)",
            admin_email,
            action,
            target or "N/A",
            result,
            extra={
                "event_type": "admin_action",
                "admin": admin_email,
                "action": action,
                "target": target,
                "result": result,
                "details": details or {},
            }
        )

    def log_auth_event(
        self,
        event_type: str,
        user_email: str | None = None,
        ip_address: str | None = None,
        result: str = "success",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log authentication event.

        Args:
            event_type: Type of auth event ("login", "logout", "failed_auth")
            user_email: User's email address
            ip_address: IP address of request
            result: Result of event ("success", "failure")
            details: Additional details dictionary
        """
        self.logger.info(
            "AUTH_EVENT: %s for %s from %s (result: %s)",
            event_type,
            user_email or "anonymous",
            ip_address or "unknown",
            result,
            extra={
                "event_type": "auth_event",
                "auth_event_type": event_type,
                "user": user_email,
                "ip": ip_address,
                "result": result,
                "details": details or {},
            }
        )

    def log_access_denied(
        self,
        user_email: str,
        resource: str,
        reason: str,
        ip_address: str | None = None,
    ) -> None:
        """Log access denial.

        Args:
            user_email: User's email address
            resource: Resource that was denied
            reason: Reason for denial
            ip_address: IP address of request
        """
        self.logger.warning(
            "ACCESS_DENIED: %s denied access to %s (reason: %s) from %s",
            user_email,
            resource,
            reason,
            ip_address or "unknown",
            extra={
                "event_type": "access_denied",
                "user": user_email,
                "resource": resource,
                "reason": reason,
                "ip": ip_address,
            }
        )

    def log_security_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log general security event.

        Args:
            event_type: Type of security event
            severity: Severity level ("low", "medium", "high", "critical")
            description: Event description
            details: Additional details dictionary
        """
        log_method = {
            "low": self.logger.info,
            "medium": self.logger.warning,
            "high": self.logger.error,
            "critical": self.logger.critical,
        }.get(severity, self.logger.warning)

        log_method(
            "SECURITY_EVENT: %s [%s] - %s",
            event_type,
            severity.upper(),
            description,
            extra={
                "event_type": "security_event",
                "security_event_type": event_type,
                "severity": severity,
                "description": description,
                "details": details or {},
            }
        )


def get_audit_logger() -> AuditLogger:
    """Get singleton audit logger instance.

    Returns:
        AuditLogger instance
    """
    if not hasattr(get_audit_logger, "_instance"):
        get_audit_logger._instance = AuditLogger()
    return get_audit_logger._instance
