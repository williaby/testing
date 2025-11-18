"""Email whitelist management for Cloudflare authentication.

This module provides email whitelist validation with domain support,
enabling authorization of specific emails or entire domains (@company.com).
Supports both individual email addresses, admin privilege detection, and user tier management.

Key Features:
    - Individual email whitelisting
    - Domain pattern support (@company.com allows all @company.com emails)
    - User tiers (admin/full/limited) for feature access control
    - Premium model access control
    - Runtime whitelist management

Dependencies:
    - pydantic: For configuration validation
    - logging: For audit trails

Called by:
    - src.cloudflare_auth.middleware: For authorization checks
    - Application code: For access control decisions
"""

from dataclasses import dataclass
from enum import Enum
import logging
import secrets
from typing import Any

from pydantic import BaseModel, field_validator

try:
    from email_validator import validate_email, EmailNotValidError
    EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    EMAIL_VALIDATOR_AVAILABLE = False
    EmailNotValidError = None  # type: ignore


logger = logging.getLogger(__name__)


class UserTier(str, Enum):
    """User access tiers for model and feature restrictions.

    Attributes:
        ADMIN: Full access plus administrative privileges
        FULL: Full access to all features and premium models
        LIMITED: Limited access to basic features only
    """

    ADMIN = "admin"
    FULL = "full"
    LIMITED = "limited"

    @classmethod
    def from_string(cls, value: str) -> "UserTier":
        """Create UserTier from string value.

        Args:
            value: String representation of tier

        Returns:
            UserTier enum value

        Raises:
            ValueError: If value is not a valid tier
        """
        value = value.lower().strip()
        for tier in cls:
            if tier.value == value:
                return tier
        raise ValueError(f"Invalid user tier: {value}")

    @property
    def can_access_premium_models(self) -> bool:
        """Check if tier allows access to premium models.

        Returns:
            True for ADMIN and FULL tiers, False for LIMITED
        """
        return self in (UserTier.ADMIN, UserTier.FULL)

    @property
    def has_admin_privileges(self) -> bool:
        """Check if tier has admin privileges.

        Returns:
            True only for ADMIN tier
        """
        return self == UserTier.ADMIN


@dataclass
class WhitelistEntry:
    """Represents a whitelist entry with metadata.

    Attributes:
        value: Email address or domain pattern (@domain.com)
        is_domain: Whether this is a domain pattern vs individual email
        added_at: ISO timestamp when entry was added
        description: Optional description of why this entry exists
    """

    value: str
    is_domain: bool
    added_at: str
    description: str | None = None


class EmailWhitelistConfig(BaseModel):
    """Configuration for email whitelist validation.

    This Pydantic model validates and normalizes whitelist configuration
    from environment variables or config files.

    Attributes:
        whitelist: List of allowed emails/domains
        admin_emails: List of emails with admin privileges
        full_users: List of emails with full tier access
        limited_users: List of emails with limited tier access
        case_sensitive: Whether email matching is case-sensitive
    """

    whitelist: list[str] = []
    admin_emails: list[str] = []
    full_users: list[str] = []
    limited_users: list[str] = []
    case_sensitive: bool = False

    @field_validator("whitelist", "admin_emails", "full_users", "limited_users", mode="before")
    @classmethod
    def normalize_emails(cls, v: str | list[str]) -> list[str]:
        """Normalize email addresses to lowercase unless case_sensitive.

        Args:
            v: String (comma-separated) or list of emails

        Returns:
            List of normalized email addresses
        """
        if isinstance(v, str):
            v = [email.strip() for email in v.split(",") if email.strip()]
        return [email.strip().lower() for email in v] if v else []


class EmailWhitelistValidator:
    """Email whitelist validator with domain support.

    Validates email addresses against a whitelist that can contain:
    - Individual email addresses: user@example.com
    - Domain patterns: @company.com (allows any email from that domain)
    - Admin privilege detection for specific admin emails
    - User tier assignment (admin/full/limited)

    Example:
        validator = EmailWhitelistValidator(
            whitelist=["user@example.com", "@company.com"],
            admin_emails=["admin@company.com"],
            full_users=["@company.com"],
            limited_users=["contractor@external.com"]
        )

        if validator.is_authorized("test@company.com"):
            tier = validator.get_user_tier("test@company.com")
            if tier.can_access_premium_models:
                # Allow premium access
                pass
    """

    def __init__(
        self,
        whitelist: list[str],
        admin_emails: list[str] | None = None,
        full_users: list[str] | None = None,
        limited_users: list[str] | None = None,
        case_sensitive: bool = False,
    ) -> None:
        """Initialize the email whitelist validator.

        Args:
            whitelist: List of allowed emails and domains
            admin_emails: List of emails with admin privileges
            full_users: List of emails with full tier access
            limited_users: List of emails with limited tier access
            case_sensitive: Whether email matching should be case-sensitive
        """
        self.case_sensitive = case_sensitive
        self.admin_emails = self._normalize_emails(admin_emails or [])
        self.full_users = self._normalize_emails(full_users or [])
        self.limited_users = self._normalize_emails(limited_users or [])

        # Separate individual emails from domain patterns
        self.individual_emails = set()
        self.domain_patterns = set()

        for entry in self._normalize_emails(whitelist):
            if entry.startswith("@"):
                self.domain_patterns.add(entry)
            else:
                self.individual_emails.add(entry)

        logger.info(
            "Initialized email whitelist: %d individual emails, %d domain patterns, "
            "%d admin emails, %d full users, %d limited users",
            len(self.individual_emails),
            len(self.domain_patterns),
            len(self.admin_emails),
            len(self.full_users),
            len(self.limited_users),
        )

    def _normalize_emails(self, emails: list[str]) -> list[str]:
        """Normalize email list based on case sensitivity setting.

        Args:
            emails: List of email addresses to normalize

        Returns:
            Normalized list of emails
        """
        if not emails:
            return []

        normalized = []
        for email_item in emails:
            email = email_item.strip()
            if email:
                normalized.append(email if self.case_sensitive else email.lower())

        return normalized

    def _normalize_email(self, email: str) -> str:
        """Normalize a single email address.

        Args:
            email: Email address to normalize

        Returns:
            Normalized email address
        """
        return email.strip() if self.case_sensitive else email.strip().lower()

    def is_authorized(self, email: str) -> bool:
        """Check if email is authorized via whitelist.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            email: Email address to validate

        Returns:
            True if email is authorized, False otherwise
        """
        if not email:
            return False

        normalized_email = self._normalize_email(email)

        # Check individual email whitelist using constant-time comparison
        for allowed_email in self.individual_emails:
            if secrets.compare_digest(normalized_email, allowed_email):
                logger.debug("Email %s authorized via individual whitelist", email)
                return True

        # Check domain patterns using constant-time comparison
        if "@" in normalized_email:
            domain = "@" + normalized_email.split("@")[1]
            for allowed_domain in self.domain_patterns:
                if secrets.compare_digest(domain, allowed_domain):
                    logger.debug("Email %s authorized via domain pattern %s", email, domain)
                    return True

        logger.debug("Email %s not authorized", email)
        return False

    def is_admin(self, email: str) -> bool:
        """Check if email has admin privileges.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            email: Email address to check

        Returns:
            True if email is an admin, False otherwise
        """
        if not email:
            return False

        normalized_email = self._normalize_email(email)

        # Use constant-time comparison to prevent timing attacks
        for admin_email in self.admin_emails:
            if secrets.compare_digest(normalized_email, admin_email):
                logger.debug("Email %s has admin privileges", email)
                return True

        return False

    def get_user_role(self, email: str) -> str:
        """Get user role based on email.

        Args:
            email: Email address to check

        Returns:
            'admin', 'user', or 'unauthorized'
        """
        if not self.is_authorized(email):
            return "unauthorized"

        return "admin" if self.is_admin(email) else "user"

    def get_user_tier(self, email: str) -> UserTier:
        """Get user tier based on email.

        Checks in priority order: admin -> full -> limited
        First checks exact email matches, then domain patterns.

        Args:
            email: Email address to check

        Returns:
            UserTier enum value

        Raises:
            ValueError: If email is not authorized
        """
        if not email:
            raise ValueError("Email cannot be empty")

        if not self.is_authorized(email):
            raise ValueError(f"Email {email} is not authorized")

        normalized_email = self._normalize_email(email)

        # Check tiers in priority order
        tier_lists = (self.admin_emails, self.full_users, self.limited_users)
        tier_types = (UserTier.ADMIN, UserTier.FULL, UserTier.LIMITED)

        # First check exact email matches
        for tier_list, tier_type in zip(tier_lists, tier_types, strict=False):
            if normalized_email in tier_list:
                logger.debug("Email %s has %s tier (exact match)", email, tier_type.value)
                return tier_type

        # Then check domain pattern matches
        if "@" in normalized_email:
            domain = "@" + normalized_email.split("@")[1]
            for tier_list, tier_type in zip(tier_lists, tier_types, strict=False):
                if domain in tier_list:
                    logger.debug(
                        "Email %s has %s tier (domain match: %s)",
                        email,
                        tier_type.value,
                        domain,
                    )
                    return tier_type

        # Default to limited tier for authorized users not explicitly assigned
        logger.debug("Email %s defaulted to limited tier", email)
        return UserTier.LIMITED

    def can_access_premium_models(self, email: str) -> bool:
        """Check if email can access premium models.

        Args:
            email: Email address to check

        Returns:
            True if user can access premium models, False otherwise
        """
        try:
            tier = self.get_user_tier(email)
            return tier.can_access_premium_models
        except ValueError:
            return False

    def has_admin_privileges(self, email: str) -> bool:
        """Check if email has admin privileges.

        Args:
            email: Email address to check

        Returns:
            True if user has admin privileges, False otherwise
        """
        try:
            tier = self.get_user_tier(email)
            return tier.has_admin_privileges
        except ValueError:
            return False

    def get_whitelist_stats(self) -> dict[str, Any]:
        """Get statistics about the current whitelist configuration.

        Returns:
            Dictionary with whitelist statistics
        """
        return {
            "individual_emails": len(self.individual_emails),
            "domain_patterns": len(self.domain_patterns),
            "admin_emails": len(self.admin_emails),
            "full_users": len(self.full_users),
            "limited_users": len(self.limited_users),
            "total_entries": len(self.individual_emails) + len(self.domain_patterns),
            "case_sensitive": self.case_sensitive,
            "domains": list(self.domain_patterns),
            "tier_distribution": {
                "admin": len(self.admin_emails),
                "full": len(self.full_users),
                "limited": len(self.limited_users),
            },
        }

    def validate_whitelist_config(self) -> list[str]:
        """Validate the whitelist configuration and return any warnings.

        Returns:
            List of warning messages about the configuration
        """
        warnings = []

        # Check for empty whitelist
        if not self.individual_emails and not self.domain_patterns:
            warnings.append("Whitelist is empty - no users will be authorized")

        # Check for admin emails not in whitelist
        for admin_email in self.admin_emails:
            if not self.is_authorized(admin_email):
                warnings.append(f"Admin email {admin_email} is not in whitelist")

        # Check for full users not in whitelist
        for full_user in self.full_users:
            if not self.is_authorized(full_user):
                warnings.append(f"Full user email {full_user} is not in whitelist")

        # Check for limited users not in whitelist
        for limited_user in self.limited_users:
            if not self.is_authorized(limited_user):
                warnings.append(f"Limited user email {limited_user} is not in whitelist")

        # Check for tier conflicts
        all_tier_emails = set(self.admin_emails) | set(self.full_users) | set(self.limited_users)
        for email in all_tier_emails:
            tiers = []
            if email in self.admin_emails:
                tiers.append("admin")
            if email in self.full_users:
                tiers.append("full")
            if email in self.limited_users:
                tiers.append("limited")

            if len(tiers) > 1:
                warnings.append(f"Email {email} is assigned to multiple tiers: {', '.join(tiers)}")

        # Check for potential security issues
        if "@gmail.com" in self.domain_patterns or "@outlook.com" in self.domain_patterns:
            warnings.append("Public email domains (@gmail.com, @outlook.com) in whitelist may be insecure")

        return warnings


class WhitelistManager:
    """Manager for dynamic whitelist operations.

    Provides runtime management of whitelist entries. Note that changes
    are not persisted - for permanent changes, update configuration.

    Example:
        manager = WhitelistManager(validator)
        manager.add_email("newuser@company.com")
        status = manager.check_email("newuser@company.com")
    """

    def __init__(self, validator: EmailWhitelistValidator) -> None:
        """Initialize whitelist manager with a validator.

        Args:
            validator: EmailWhitelistValidator instance to manage
        """
        self.validator = validator

    def add_email(self, email: str, is_admin: bool = False) -> bool:
        """Add email to whitelist (runtime operation).

        Note: This is for runtime operations. For persistent changes,
        update the configuration file directly.

        Args:
            email: Email or domain pattern to add
            is_admin: Whether email should have admin privileges

        Returns:
            True if email was added successfully

        Raises:
            ValueError: If email format is invalid
        """
        try:
            # Validate input is not empty
            if not email or not email.strip():
                raise ValueError("Email cannot be empty")

            normalized_email = self.validator._normalize_email(email)

            # Validate email format (if not a domain pattern)
            if not normalized_email.startswith("@"):
                if EMAIL_VALIDATOR_AVAILABLE and validate_email is not None:
                    try:
                        # Validate email format
                        valid = validate_email(normalized_email, check_deliverability=False)
                        normalized_email = valid.normalized if not self.validator.case_sensitive else normalized_email
                    except EmailNotValidError as e:
                        raise ValueError(f"Invalid email format: {str(e)}") from e
                else:
                    # Basic email validation if email-validator not available
                    if "@" not in normalized_email or normalized_email.count("@") != 1:
                        raise ValueError("Invalid email format: must contain exactly one @")

                    local, domain = normalized_email.split("@")
                    if not local or not domain or "." not in domain:
                        raise ValueError("Invalid email format")

            # Validate domain pattern format
            else:
                # Domain pattern must be @domain.tld format
                if normalized_email.count("@") != 1:
                    raise ValueError("Invalid domain pattern: must be @domain.tld")

                domain_part = normalized_email[1:]  # Remove @
                if not domain_part or "." not in domain_part:
                    raise ValueError("Invalid domain pattern: must include valid domain")

            # Add to appropriate collection
            if normalized_email.startswith("@"):
                self.validator.domain_patterns.add(normalized_email)
            else:
                self.validator.individual_emails.add(normalized_email)

            if is_admin:
                self.validator.admin_emails.append(normalized_email)

            logger.info("Added email %s to whitelist (admin: %s)", email, is_admin)
            return True

        except ValueError:
            # Re-raise validation errors
            raise
        except Exception as e:
            logger.error("Failed to add email %s to whitelist: %s", email, e)
            raise ValueError(f"Failed to add email: {str(e)}") from e

    def remove_email(self, email: str) -> bool:
        """Remove email from whitelist (runtime operation).

        Args:
            email: Email or domain pattern to remove

        Returns:
            True if email was removed successfully
        """
        try:
            normalized_email = self.validator._normalize_email(email)

            # Remove from individual emails or domain patterns
            removed = False
            if normalized_email in self.validator.individual_emails:
                self.validator.individual_emails.remove(normalized_email)
                removed = True

            if normalized_email in self.validator.domain_patterns:
                self.validator.domain_patterns.remove(normalized_email)
                removed = True

            # Remove from admin emails if present
            if normalized_email in self.validator.admin_emails:
                self.validator.admin_emails.remove(normalized_email)

            if removed:
                logger.info("Removed email %s from whitelist", email)
            else:
                logger.warning("Email %s not found in whitelist", email)

            return removed

        except Exception as e:
            logger.error("Failed to remove email %s from whitelist: %s", email, e)
            return False

    def check_email(self, email: str) -> dict[str, Any]:
        """Check email status and provide detailed information.

        Args:
            email: Email to check

        Returns:
            Dictionary with email status information
        """
        return {
            "email": email,
            "is_authorized": self.validator.is_authorized(email),
            "is_admin": self.validator.is_admin(email),
            "role": self.validator.get_user_role(email),
            "normalized_email": self.validator._normalize_email(email),
        }


def create_validator_from_env(
    whitelist_str: str,
    admin_emails_str: str = "",
    full_users_str: str = "",
    limited_users_str: str = "",
) -> EmailWhitelistValidator:
    """Create EmailWhitelistValidator from environment variable strings.

    This is a convenience function for creating validators from
    comma-separated environment variable values.

    Args:
        whitelist_str: Comma-separated string of emails/domains
        admin_emails_str: Comma-separated string of admin emails
        full_users_str: Comma-separated string of full tier users
        limited_users_str: Comma-separated string of limited tier users

    Returns:
        Configured EmailWhitelistValidator

    Example:
        validator = create_validator_from_env(
            whitelist_str="user@example.com,@company.com",
            admin_emails_str="admin@company.com",
            full_users_str="@company.com"
        )
    """
    whitelist = (
        [email.strip() for email in whitelist_str.split(",") if email.strip()]
        if whitelist_str
        else []
    )
    admin_emails = (
        [email.strip() for email in admin_emails_str.split(",") if email.strip()]
        if admin_emails_str
        else []
    )
    full_users = (
        [email.strip() for email in full_users_str.split(",") if email.strip()]
        if full_users_str
        else []
    )
    limited_users = (
        [email.strip() for email in limited_users_str.split(",") if email.strip()]
        if limited_users_str
        else []
    )

    return EmailWhitelistValidator(
        whitelist=whitelist,
        admin_emails=admin_emails,
        full_users=full_users,
        limited_users=limited_users,
    )
