"""JWT validation utilities for Cloudflare Access tokens.

This module provides comprehensive JWT token validation using Cloudflare's
public certificates. It implements proper cryptographic verification,
claim validation, and certificate caching.

Key Components:
    - CloudflareJWTValidator: Main validator class
    - Certificate caching for performance
    - Audience and issuer validation
    - Expiration checking

Architecture:
    The validator fetches Cloudflare's public certificates and caches them
    for efficient token validation. It verifies the JWT signature using
    RS256 algorithm and validates all required claims.

Dependencies:
    - PyJWT: For JWT encoding/decoding
    - cryptography: For RSA key handling
    - httpx: For async certificate fetching
    - src.config.settings: For Cloudflare configuration

Called by:
    - src.cloudflare_auth.middleware: During request authentication
    - Application security layer: For token validation

Complexity: O(1) for cached certificates, O(n) for initial fetch
"""

import logging
from datetime import datetime, timedelta
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

from src.cloudflare_auth.models import CloudflareJWTClaims
from src.config.settings import CloudflareSettings, get_cloudflare_settings


logger = logging.getLogger(__name__)


class CloudflareJWTValidator:
    """Validates JWT tokens from Cloudflare Access.

    This class handles all aspects of JWT validation including:
    - Signature verification using Cloudflare's public keys
    - Audience and issuer validation
    - Expiration checking
    - Claim extraction and validation

    Attributes:
        settings: Cloudflare configuration settings
        jwks_client: Client for fetching JWT signing keys
        _last_key_refresh: Timestamp of last key refresh

    Example:
        validator = CloudflareJWTValidator()
        try:
            claims = validator.validate_token(jwt_token)
            print(f"Authenticated: {claims.email}")
        except ValueError as e:
            print(f"Authentication failed: {e}")
    """

    def __init__(self, settings: CloudflareSettings | None = None) -> None:
        """Initialize JWT validator.

        Args:
            settings: Optional CloudflareSettings instance (uses default if not provided)
        """
        self.settings = settings or get_cloudflare_settings()

        if not self.settings.cloudflare_team_domain:
            logger.warning(
                "Cloudflare team domain not configured. JWT validation will fail."
            )

        # Initialize JWKS client for fetching public keys
        if self.settings.certs_url:
            self.jwks_client = PyJWKClient(
                self.settings.certs_url,
                cache_keys=True,
                max_cached_keys=self.settings.jwt_cache_max_keys,
            )
        else:
            self.jwks_client = None

        self._last_key_refresh: datetime | None = None

    def validate_token(
        self,
        token: str,
        verify_exp: bool = True,
    ) -> CloudflareJWTClaims:
        """Validate a Cloudflare Access JWT token.

        This method performs comprehensive validation:
        1. Signature verification using Cloudflare's public keys
        2. Expiration time validation
        3. Issuer validation
        4. Audience validation
        5. Required claims presence

        Args:
            token: JWT token string from Cf-Access-Jwt-Assertion header
            verify_exp: Whether to verify token expiration (default: True)

        Returns:
            CloudflareJWTClaims object with validated claims

        Raises:
            ValueError: If token is invalid, expired, or claims are missing
            RuntimeError: If validator is not properly configured

        Time Complexity: O(1) with cached keys, O(n) on cache miss
        Space Complexity: O(1) for token validation

        Called by:
            - CloudflareAuthMiddleware.authenticate_request()
            - Manual token validation in endpoints

        Example:
            validator = CloudflareJWTValidator()
            try:
                claims = validator.validate_token(token)
                if claims.email == "admin@example.com":
                    # Grant admin access
                    pass
            except ValueError as e:
                # Handle authentication failure
                logger.error(f"Auth failed: {e}")
        """
        if not self.jwks_client:
            raise RuntimeError(
                "JWT validator not configured. Set CLOUDFLARE_TEAM_DOMAIN."
            )

        try:
            # Get the signing key from the JWT header
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and validate the token
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=[self.settings.jwt_algorithm],
                audience=self.settings.cloudflare_audience_tag,
                issuer=self.settings.issuer,
                options={
                    "verify_exp": verify_exp,
                    "verify_aud": bool(self.settings.cloudflare_audience_tag),
                    "verify_iss": bool(self.settings.issuer),
                },
            )

            # Validate required claims
            self._validate_required_claims(payload)

            # Create and return claims object
            claims = CloudflareJWTClaims(**payload)

            # Additional validation
            if self.settings.require_email_verification and not claims.email:
                raise ValueError("Email claim is required but missing")

            # Check email domain if restrictions are configured
            if not self.settings.is_email_allowed(claims.email):
                raise ValueError(
                    f"Email domain not allowed: {claims.email}"
                )

            logger.debug(
                "Successfully validated JWT for user: %s",
                claims.email,
            )

            return claims

        except jwt.ExpiredSignatureError as e:
            logger.warning("JWT token expired: %s", str(e))
            raise ValueError("Token has expired") from e

        except jwt.InvalidAudienceError as e:
            logger.warning("Invalid JWT audience: %s", str(e))
            raise ValueError("Invalid token audience") from e

        except jwt.InvalidIssuerError as e:
            logger.warning("Invalid JWT issuer: %s", str(e))
            raise ValueError("Invalid token issuer") from e

        except jwt.InvalidSignatureError as e:
            logger.warning("Invalid JWT signature: %s", str(e))
            raise ValueError("Invalid token signature") from e

        except jwt.DecodeError as e:
            logger.warning("Failed to decode JWT: %s", str(e))
            raise ValueError("Invalid token format") from e

        except Exception as e:
            logger.error("Unexpected error validating JWT: %s", str(e))
            raise ValueError(f"Token validation failed: {str(e)}") from e

    def _validate_required_claims(self, payload: dict[str, Any]) -> None:
        """Validate that required claims are present.

        Args:
            payload: Decoded JWT payload

        Raises:
            ValueError: If required claims are missing
        """
        required_claims = ["email", "iss", "aud", "sub", "iat", "exp"]

        missing_claims = [
            claim for claim in required_claims if claim not in payload
        ]

        if missing_claims:
            raise ValueError(
                f"Missing required JWT claims: {', '.join(missing_claims)}"
            )

    async def validate_token_async(
        self,
        token: str,
        verify_exp: bool = True,
    ) -> CloudflareJWTClaims:
        """Async version of validate_token.

        This method provides the same validation as validate_token but
        can be used in async contexts. Note that JWT validation itself
        is CPU-bound and not truly async.

        Args:
            token: JWT token string
            verify_exp: Whether to verify token expiration

        Returns:
            CloudflareJWTClaims object with validated claims

        Raises:
            ValueError: If token is invalid
        """
        # JWT validation is CPU-bound, not I/O bound
        # But we provide async interface for consistency
        return self.validate_token(token, verify_exp=verify_exp)

    def refresh_keys(self) -> None:
        """Force refresh of cached public keys.

        This method can be called to manually refresh the cached
        Cloudflare public keys. Useful for handling key rotation.

        Note:
            PyJWKClient handles key caching automatically. Creating a new
            instance will fetch fresh keys on next validation.
        """
        if self.jwks_client and self.settings.certs_url:
            # Create a new JWKS client to force key refresh
            # This is safer than accessing private attributes
            self.jwks_client = PyJWKClient(
                self.settings.certs_url,
                cache_keys=True,
                max_cached_keys=self.settings.jwt_cache_max_keys,
            )
            self._last_key_refresh = datetime.now()
            logger.info("Cloudflare public keys client refreshed")

    @property
    def is_configured(self) -> bool:
        """Check if validator is properly configured.

        Returns:
            True if validator has necessary configuration
        """
        return bool(
            self.settings.cloudflare_team_domain
            and self.settings.cloudflare_audience_tag
            and self.jwks_client
        )

    def get_unverified_claims(self, token: str) -> dict[str, Any]:
        """Get claims from token without verification.

        WARNING: This method does NOT verify the token signature.
        Only use for debugging or non-security-critical inspection.

        Args:
            token: JWT token string

        Returns:
            Dictionary of unverified claims

        Example:
            # For debugging only
            claims = validator.get_unverified_claims(token)
            print(f"Token issued for: {claims.get('email')}")
        """
        try:
            return jwt.decode(
                token,
                options={"verify_signature": False},
            )
        except Exception as e:
            logger.error("Failed to decode token: %s", str(e))
            return {}
