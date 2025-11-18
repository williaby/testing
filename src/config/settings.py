"""Configuration settings for Cloudflare Access authentication.

This module provides Pydantic-based configuration management for Cloudflare Access,
supporting environment variables and secure secret management.

Key Features:
    - Environment-based configuration (dev, staging, prod)
    - JWT validation settings
    - Audience and issuer validation
    - Whitelisted email domains
    - Certificate caching

Dependencies:
    - pydantic: For settings validation and management
    - pydantic-settings: For environment variable loading

Called by:
    - src.cloudflare_auth.middleware: For authentication configuration
    - src.cloudflare_auth.validators: For JWT validation settings
"""

import logging
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


logger = logging.getLogger(__name__)


class CloudflareSettings(BaseSettings):
    """Settings for Cloudflare Access authentication.

    This class manages all configuration required for Cloudflare Access
    authentication including JWT validation, team information, and
    security policies.

    Attributes:
        environment: Deployment environment (dev, staging, prod)
        cloudflare_team_domain: Your Cloudflare team domain (e.g., myteam.cloudflareaccess.com)
        cloudflare_audience_tag: Application audience tag from Cloudflare Access
        cloudflare_enabled: Whether to enforce Cloudflare authentication
        allowed_email_domains: List of allowed email domains for additional validation
        jwt_algorithm: Algorithm used for JWT validation
        jwt_cache_max_keys: Maximum number of public keys to cache
        require_email_verification: Whether to require verified emails
        log_auth_failures: Whether to log authentication failures

    Example:
        # Via environment variables
        export CLOUDFLARE_TEAM_DOMAIN="myteam.cloudflareaccess.com"
        export CLOUDFLARE_AUDIENCE_TAG="abc123..."

        settings = get_cloudflare_settings()
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Environment
    environment: Literal["dev", "staging", "prod"] = Field(
        default="dev",
        description="Deployment environment",
    )

    # Cloudflare Access Configuration
    cloudflare_team_domain: str = Field(
        default="",
        description="Your Cloudflare team domain (e.g., myteam.cloudflareaccess.com)",
    )

    cloudflare_audience_tag: str = Field(
        default="",
        description="Application audience tag from Cloudflare Access dashboard",
    )

    cloudflare_enabled: bool = Field(
        default=True,
        description="Whether to enforce Cloudflare authentication",
    )

    # Email Validation
    allowed_email_domains: list[str] = Field(
        default_factory=list,
        description="Optional list of allowed email domains (e.g., ['example.com'])",
    )

    # JWT Configuration
    jwt_algorithm: str = Field(
        default="RS256",
        description="JWT signature algorithm (RS256 for Cloudflare)",
    )

    jwt_cache_max_keys: int = Field(
        default=10,
        description="Maximum number of public keys to cache",
    )

    # Security Settings
    require_email_verification: bool = Field(
        default=True,
        description="Require email verification in JWT claims",
    )

    log_auth_failures: bool = Field(
        default=True,
        description="Log authentication failures for security monitoring",
    )

    # Cloudflare Origin Validation (Tunnel Security)
    require_cloudflare_headers: bool = Field(
        default=True,
        description="Require Cloudflare headers to prove request came through tunnel (recommended for production)",
    )

    allowed_tunnel_ips: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "::1"],
        description="IP addresses allowed to connect (tunnel IPs). Empty list = allow all (not recommended).",
    )

    # Header Configuration
    jwt_header_name: str = Field(
        default="Cf-Access-Jwt-Assertion",
        description="Header containing the JWT assertion",
    )

    email_header_name: str = Field(
        default="Cf-Access-Authenticated-User-Email",
        description="Header containing authenticated user email",
    )

    # Cookie Configuration
    cookie_domain: str | None = Field(
        default=None,
        description="Domain for session cookies (e.g., '.example.com'). None = current domain",
    )

    cookie_path: str = Field(
        default="/",
        description="Path for session cookies",
    )

    cookie_secure: bool = Field(
        default=True,
        description="Require HTTPS for cookies (should be True in production)",
    )

    cookie_samesite: str = Field(
        default="strict",
        description="SameSite cookie attribute (strict, lax, or none)",
    )

    @field_validator("cloudflare_enabled")
    @classmethod
    def validate_cloudflare_enabled(cls, v: bool, info) -> bool:
        """Validate Cloudflare authentication is enabled in production.

        Args:
            v: cloudflare_enabled value
            info: Field validation info

        Returns:
            Validated cloudflare_enabled value

        Raises:
            ValueError: If disabled in production environment
        """
        # Get environment from validation context
        environment = info.data.get("environment", "dev")

        # CRITICAL: Prevent disabling auth in production
        if not v and environment in ["prod", "production"]:
            raise ValueError(
                "\n" + "="*80 + "\n"
                "🔴 SECURITY ERROR: cloudflare_enabled=False in PRODUCTION! 🔴\n"
                "="*80 + "\n"
                "Cloudflare authentication is DISABLED in a production environment.\n"
                "This completely disables all authentication and authorization.\n"
                "\n"
                "ALL ENDPOINTS WILL BE PUBLICLY ACCESSIBLE WITHOUT AUTHENTICATION!\n"
                "\n"
                "To fix this, set: CLOUDFLARE_ENABLED=true\n"
                "="*80 + "\n"
            )

        # Warning for non-production environments
        if not v:
            warning_msg = (
                "\n" + "="*80 + "\n"
                "⚠️  SECURITY WARNING: AUTHENTICATION DISABLED ⚠️\n"
                "="*80 + "\n"
                f"Environment: {environment}\n"
                "Cloudflare authentication is currently DISABLED.\n"
                "All endpoints are publicly accessible without authentication.\n"
                "\n"
                "This should ONLY be used in local development environments.\n"
                "\n"
                "To enable authentication, set: CLOUDFLARE_ENABLED=true\n"
                "="*80 + "\n"
            )
            logger.warning(warning_msg)
            print(warning_msg, flush=True)  # Also print to console

        return v

    @field_validator("cloudflare_team_domain")
    @classmethod
    def validate_team_domain(cls, v: str) -> str:
        """Validate team domain format.

        Args:
            v: Team domain value

        Returns:
            Validated team domain

        Raises:
            ValueError: If domain format is invalid
        """
        if v and not v.endswith(".cloudflareaccess.com"):
            raise ValueError(
                "Team domain must end with '.cloudflareaccess.com' "
                f"(got: {v})"
            )
        return v

    @field_validator("allowed_email_domains")
    @classmethod
    def validate_email_domains(cls, v: list[str]) -> list[str]:
        """Validate and normalize email domains.

        Args:
            v: List of email domains

        Returns:
            Normalized list of email domains (lowercase)
        """
        return [domain.lower().strip() for domain in v]

    @property
    def certs_url(self) -> str:
        """Get the URL for Cloudflare's public certificates.

        Returns:
            URL to fetch public certificates for JWT validation
        """
        if not self.cloudflare_team_domain:
            return ""
        return f"https://{self.cloudflare_team_domain}/cdn-cgi/access/certs"

    @property
    def issuer(self) -> str:
        """Get the expected JWT issuer.

        Returns:
            Expected issuer URL for JWT validation
        """
        if not self.cloudflare_team_domain:
            return ""
        return f"https://{self.cloudflare_team_domain}"

    def is_email_allowed(self, email: str) -> bool:
        """Check if an email address is in allowed domains.

        Args:
            email: Email address to check

        Returns:
            True if email is allowed, or if no domain restrictions are set
        """
        if not self.allowed_email_domains:
            # No restrictions if list is empty
            return True

        email_lower = email.lower()
        domain = email_lower.split("@")[-1] if "@" in email_lower else ""

        return domain in self.allowed_email_domains


@lru_cache()
def get_cloudflare_settings() -> CloudflareSettings:
    """Get cached Cloudflare settings instance.

    This function returns a singleton settings instance that is
    cached for the lifetime of the application.

    Returns:
        CloudflareSettings instance

    Example:
        settings = get_cloudflare_settings()
        if settings.cloudflare_enabled:
            # Enable authentication
            pass
    """
    return CloudflareSettings()
