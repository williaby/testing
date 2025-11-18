"""Data models for Cloudflare Access authentication.

This module provides Pydantic models representing authenticated users
and JWT claims from Cloudflare Access.

Key Components:
    - CloudflareUser: Represents an authenticated user with tier and admin support
    - CloudflareJWTClaims: JWT token claims structure

Dependencies:
    - pydantic: For data validation and serialization
    - src.cloudflare_auth.whitelist: For UserTier enum

Called by:
    - src.cloudflare_auth.middleware: For user object creation
    - src.cloudflare_auth.validators: For JWT claims parsing
    - Application endpoints: For accessing user information
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field

from src.cloudflare_auth.whitelist import UserTier


class CloudflareJWTClaims(BaseModel):
    """JWT claims from Cloudflare Access token.

    This model represents the standard claims present in a Cloudflare
    Access JWT assertion token.

    Attributes:
        email: Authenticated user's email address
        iss: Token issuer (Cloudflare team domain)
        aud: Audience tag for the application
        sub: Subject (user identifier)
        iat: Issued at timestamp
        exp: Expiration timestamp
        nonce: Nonce for replay protection
        identity_nonce: Identity nonce
        custom_claims: Any additional custom claims

    Example:
        claims = CloudflareJWTClaims(
            email="user@example.com",
            iss="https://myteam.cloudflareaccess.com",
            aud=["abc123"],
            sub="user-id-123",
            iat=1234567890,
            exp=1234571490
        )
    """

    # Standard JWT claims
    email: EmailStr = Field(
        description="Authenticated user's email address"
    )
    iss: str = Field(
        description="Token issuer (Cloudflare team domain)"
    )
    aud: list[str] | str = Field(
        description="Audience tag(s) for the application"
    )
    sub: str = Field(
        description="Subject (user identifier)"
    )
    iat: int = Field(
        description="Issued at timestamp (Unix epoch)"
    )
    exp: int = Field(
        description="Expiration timestamp (Unix epoch)"
    )

    # Optional Cloudflare-specific claims
    nonce: str | None = Field(
        default=None,
        description="Nonce for replay protection"
    )
    identity_nonce: str | None = Field(
        default=None,
        description="Identity nonce"
    )
    custom: dict[str, Any] = Field(
        default_factory=dict,
        description="Custom claims from identity provider"
    )

    @property
    def issued_at(self) -> datetime:
        """Get issued at time as datetime.

        Returns:
            Datetime when token was issued
        """
        return datetime.fromtimestamp(self.iat)

    @property
    def expires_at(self) -> datetime:
        """Get expiration time as datetime.

        Returns:
            Datetime when token expires
        """
        return datetime.fromtimestamp(self.exp)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired.

        Returns:
            True if token is expired
        """
        return datetime.now() >= self.expires_at

    def get_audience_list(self) -> list[str]:
        """Get audience as a list.

        Returns:
            List of audience tags
        """
        if isinstance(self.aud, str):
            return [self.aud]
        return self.aud


class CloudflareUser(BaseModel):
    """Represents an authenticated Cloudflare Access user.

    This model provides a convenient interface to access user information
    extracted from Cloudflare Access authentication headers, including
    tier-based access control and admin privileges.

    Attributes:
        email: User's email address
        user_id: Unique user identifier from JWT subject
        claims: Full JWT claims object
        authenticated_at: When the user was authenticated
        user_tier: User's access tier (admin/full/limited)
        is_admin: Whether user has admin privileges
        session_id: Optional session identifier

    Example:
        user = CloudflareUser(
            email="user@example.com",
            user_id="user-123",
            claims=jwt_claims,
            user_tier=UserTier.ADMIN,
            is_admin=True
        )

        # Access user info in your endpoint
        @app.get("/me")
        async def get_me(request: Request) -> dict:
            user: CloudflareUser = request.state.user
            return {
                "email": user.email,
                "tier": user.user_tier.value,
                "can_access_premium": user.can_access_premium_models
            }
    """

    email: EmailStr = Field(
        description="Authenticated user's email address"
    )
    user_id: str = Field(
        description="Unique user identifier"
    )
    claims: CloudflareJWTClaims = Field(
        description="Full JWT claims from Cloudflare"
    )
    authenticated_at: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp when user was authenticated"
    )
    user_tier: UserTier = Field(
        default=UserTier.LIMITED,
        description="User's access tier"
    )
    is_admin: bool = Field(
        default=False,
        description="Whether user has admin privileges"
    )
    session_id: str | None = Field(
        default=None,
        description="Session identifier if sessions are enabled"
    )

    @classmethod
    def from_jwt_claims(
        cls,
        claims: CloudflareJWTClaims,
        user_tier: UserTier = UserTier.LIMITED,
        is_admin: bool = False,
        session_id: str | None = None,
    ) -> "CloudflareUser":
        """Create CloudflareUser from JWT claims with tier information.

        Args:
            claims: Validated JWT claims
            user_tier: User's access tier
            is_admin: Whether user has admin privileges
            session_id: Optional session identifier

        Returns:
            CloudflareUser instance

        Example:
            claims = validator.validate_token(token)
            tier = whitelist.get_user_tier(claims.email)
            user = CloudflareUser.from_jwt_claims(
                claims,
                user_tier=tier,
                is_admin=tier.has_admin_privileges
            )
        """
        return cls(
            email=claims.email,
            user_id=claims.sub,
            claims=claims,
            user_tier=user_tier,
            is_admin=is_admin,
            session_id=session_id,
        )

    @property
    def email_domain(self) -> str:
        """Get the domain from user's email.

        Returns:
            Email domain (e.g., 'example.com')
        """
        return self.email.split("@")[-1] if "@" in self.email else ""

    @property
    def email_username(self) -> str:
        """Get the username portion of email.

        Returns:
            Username before @ symbol
        """
        return self.email.split("@")[0] if "@" in self.email else self.email

    def has_email_domain(self, domain: str) -> bool:
        """Check if user's email is from a specific domain.

        Args:
            domain: Domain to check (case-insensitive)

        Returns:
            True if email domain matches

        Example:
            if user.has_email_domain("example.com"):
                # Grant additional permissions
                pass
        """
        return self.email_domain.lower() == domain.lower()

    @property
    def can_access_premium_models(self) -> bool:
        """Check if user can access premium models.

        Returns:
            True for ADMIN and FULL tiers, False for LIMITED
        """
        return self.user_tier.can_access_premium_models

    @property
    def role(self) -> str:
        """Get user role string.

        Returns:
            'admin' or 'user'
        """
        return "admin" if self.is_admin else "user"

    def model_dump_safe(self) -> dict[str, Any]:
        """Dump model with only safe fields for logging.

        Returns:
            Dictionary with safe fields (excludes sensitive claims)
        """
        return {
            "email": self.email,
            "user_id": self.user_id,
            "email_domain": self.email_domain,
            "authenticated_at": self.authenticated_at.isoformat(),
            "user_tier": self.user_tier.value,
            "is_admin": self.is_admin,
            "can_access_premium": self.can_access_premium_models,
            "role": self.role,
        }
