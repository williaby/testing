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

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
