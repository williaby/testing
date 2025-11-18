"""CSRF protection utilities for session-based authentication.

This module provides CSRF (Cross-Site Request Forgery) protection using
double-submit cookie pattern and token validation.

Key Features:
    - Double-submit cookie pattern
    - Secure token generation
    - Token validation
    - Integration with session management

Dependencies:
    - secrets: For secure token generation
    - hashlib: For token hashing

Called by:
    - src.cloudflare_auth.middleware_enhanced: For CSRF protection
"""

import hashlib
import logging
import secrets
from typing import Optional

logger = logging.getLogger(__name__)


class CSRFProtection:
    """CSRF protection using double-submit cookie pattern.

    This implementation provides CSRF protection by:
    1. Generating a random CSRF token
    2. Setting it in both a cookie and requiring it in request headers/body
    3. Validating that both values match

    Example:
        csrf = CSRFProtection()

        # Generate token for new session
        token = csrf.generate_token()

        # Set cookie in response
        response.set_cookie("csrf_token", token, httponly=False)

        # Validate on subsequent requests
        if not csrf.validate_token(cookie_token, header_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
    """

    def __init__(
        self,
        cookie_name: str = "csrf_token",
        header_name: str = "X-CSRF-Token",
        secret_key: Optional[str] = None,
    ) -> None:
        """Initialize CSRF protection.

        Args:
            cookie_name: Name of CSRF cookie (default: "csrf_token")
            header_name: Name of CSRF header (default: "X-CSRF-Token")
            secret_key: Optional secret key for token generation
        """
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.secret_key = secret_key or secrets.token_hex(32)

        logger.info(
            "Initialized CSRF protection (cookie: %s, header: %s)",
            cookie_name,
            header_name,
        )

    def generate_token(self, session_id: Optional[str] = None) -> str:
        """Generate a new CSRF token.

        Args:
            session_id: Optional session ID to bind token to

        Returns:
            CSRF token string
        """
        # Generate random token
        random_bytes = secrets.token_bytes(32)

        # Optionally bind to session ID
        if session_id:
            # Create HMAC-like token bound to session
            data = f"{session_id}{secrets.token_hex(16)}".encode()
            token = hashlib.sha256(
                self.secret_key.encode() + data
            ).hexdigest()
        else:
            # Simple random token
            token = secrets.token_urlsafe(32)

        logger.debug("Generated CSRF token (bound to session: %s)", bool(session_id))
        return token

    def validate_token(
        self,
        cookie_token: Optional[str],
        header_token: Optional[str],
        constant_time: bool = True,
    ) -> bool:
        """Validate CSRF token from cookie and header.

        Args:
            cookie_token: Token from cookie
            header_token: Token from header
            constant_time: Use constant-time comparison (default: True)

        Returns:
            True if tokens match and are valid
        """
        # Both tokens must be present
        if not cookie_token or not header_token:
            logger.warning("CSRF validation failed: Missing token")
            return False

        # Tokens must match
        if constant_time:
            # Use constant-time comparison to prevent timing attacks
            is_valid = secrets.compare_digest(cookie_token, header_token)
        else:
            is_valid = cookie_token == header_token

        if not is_valid:
            logger.warning("CSRF validation failed: Token mismatch")

        return is_valid

    def validate_request(
        self,
        request,
        methods_to_protect: set[str] = {"POST", "PUT", "DELETE", "PATCH"},
    ) -> bool:
        """Validate CSRF token for a request.

        Args:
            request: FastAPI/Starlette Request object
            methods_to_protect: HTTP methods that require CSRF validation

        Returns:
            True if validation passes or not required for this method
        """
        # Skip CSRF check for safe methods
        if request.method not in methods_to_protect:
            return True

        # Get tokens from cookie and header
        cookie_token = request.cookies.get(self.cookie_name)
        header_token = request.headers.get(self.header_name)

        # Validate
        return self.validate_token(cookie_token, header_token)


# Global CSRF protection instance
_global_csrf_protection: Optional[CSRFProtection] = None


def get_csrf_protection(
    cookie_name: str = "csrf_token",
    header_name: str = "X-CSRF-Token",
) -> CSRFProtection:
    """Get or create global CSRF protection instance.

    Args:
        cookie_name: Name of CSRF cookie
        header_name: Name of CSRF header

    Returns:
        CSRFProtection instance
    """
    global _global_csrf_protection

    if _global_csrf_protection is None:
        _global_csrf_protection = CSRFProtection(
            cookie_name=cookie_name,
            header_name=header_name,
        )

    return _global_csrf_protection
