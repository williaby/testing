"""Session management for Cloudflare authentication.

This module provides in-memory session management for authenticated users,
supporting session creation, validation, expiration, and cleanup.

Key Features:
    - In-memory session storage
    - Automatic expiration handling
    - Session cookie support
    - User tier and admin status tracking

Dependencies:
    - secrets: For secure session ID generation
    - datetime: For expiration handling

Called by:
    - src.cloudflare_auth.middleware: For session management during authentication
"""

from datetime import datetime, timedelta
import logging
import secrets
from typing import Any

logger = logging.getLogger(__name__)


class SimpleSessionManager:
    """In-memory session management for streamlined authentication.

    This manager provides session tracking for authenticated users,
    maintaining session state and handling expiration.

    ⚠️ SECURITY WARNING:
        This in-memory implementation is NOT suitable for production use:
        - Sessions are lost on application restart
        - Not shared across multiple instances
        - No persistent storage
        - Limited scalability

        For production, use RedisSessionManager (see examples) or similar
        distributed session storage with:
        - Persistence across restarts
        - Shared state across instances
        - Session fixation protection
        - Secure session lifecycle management

    Note:
        Sessions are stored in memory and will be lost on application restart.
        For production use with multiple instances, consider using a distributed
        session store (Redis, Memcached, etc.).

    Example:
        manager = SimpleSessionManager(session_timeout=3600)
        session_id = manager.create_session(
            email="user@example.com",
            is_admin=True,
            user_tier="admin"
        )
        session = manager.get_session(session_id)
    """

    def __init__(self, session_timeout: int = 3600) -> None:
        """Initialize session manager.

        Args:
            session_timeout: Session timeout in seconds (default: 1 hour)
        """
        self.sessions: dict[str, dict[str, Any]] = {}
        self.session_timeout = session_timeout
        logger.info("Initialized session manager with %ss timeout", session_timeout)

    def create_session(
        self,
        email: str,
        is_admin: bool,
        user_tier: str,
        cf_context: dict[str, Any] | None = None,
    ) -> str:
        """Create a new session for the user.

        Args:
            email: User email address
            is_admin: Whether user has admin privileges
            user_tier: User tier (admin, full, limited)
            cf_context: Additional Cloudflare context (headers, metadata)

        Returns:
            Session ID (cryptographically secure random token)

        Example:
            session_id = manager.create_session(
                email="user@example.com",
                is_admin=False,
                user_tier="full",
                cf_context={"cf_ray": "abc123"}
            )
        """
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "email": email,
            "is_admin": is_admin,
            "user_tier": user_tier,
            "created_at": datetime.now(),
            "last_accessed": datetime.now(),
            "cf_context": cf_context or {},
        }

        logger.debug(
            "Created session %s for %s (admin: %s, tier: %s)",
            session_id[:8] + "...",  # Log only first 8 chars for security
            email,
            is_admin,
            user_tier,
        )
        return session_id

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session if valid, clean up if expired.

        This method automatically handles session expiration,
        removing expired sessions and updating last accessed time
        for valid sessions.

        Args:
            session_id: Session identifier

        Returns:
            Session data if valid, None if expired or not found

        Example:
            session = manager.get_session(session_id)
            if session:
                email = session["email"]
                is_admin = session["is_admin"]
        """
        if not session_id:
            return None

        session = self.sessions.get(session_id)
        if not session:
            return None

        # Check if session is expired
        if self._is_session_expired(session):
            logger.debug(
                "Session %s expired, removing",
                session_id[:8] + "..."
            )
            del self.sessions[session_id]
            return None

        # Update last accessed time
        session["last_accessed"] = datetime.now()
        return session

    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session.

        Args:
            session_id: Session to invalidate

        Returns:
            True if session was found and removed

        Example:
            # Logout
            if manager.invalidate_session(session_id):
                logger.info("User logged out")
        """
        if session_id in self.sessions:
            email = self.sessions[session_id].get("email", "unknown")
            del self.sessions[session_id]
            logger.debug(
                "Invalidated session %s for %s",
                session_id[:8] + "...",
                email
            )
            return True
        return False

    def refresh_session(self, session_id: str) -> bool:
        """Refresh a session's last accessed time.

        Args:
            session_id: Session to refresh

        Returns:
            True if session was found and refreshed
        """
        session = self.sessions.get(session_id)
        if session:
            session["last_accessed"] = datetime.now()
            return True
        return False

    def _is_session_expired(self, session: dict[str, Any]) -> bool:
        """Check if session has expired.

        Args:
            session: Session data dictionary

        Returns:
            True if session has exceeded timeout
        """
        expiry = session["last_accessed"] + timedelta(seconds=self.session_timeout)
        return datetime.now() >= expiry

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions from memory.

        This method should be called periodically to clean up
        expired sessions and free memory.

        Returns:
            Number of sessions cleaned up

        Example:
            # In a background task
            async def cleanup_task():
                while True:
                    count = manager.cleanup_expired_sessions()
                    if count > 0:
                        logger.info(f"Cleaned up {count} expired sessions")
                    await asyncio.sleep(300)  # Every 5 minutes
        """
        expired_sessions = [
            session_id
            for session_id, session in self.sessions.items()
            if self._is_session_expired(session)
        ]

        for session_id in expired_sessions:
            del self.sessions[session_id]

        if expired_sessions:
            logger.debug("Cleaned up %d expired sessions", len(expired_sessions))

        return len(expired_sessions)

    def get_session_count(self) -> int:
        """Get the current number of active sessions.

        Returns:
            Number of active sessions
        """
        return len(self.sessions)

    def get_user_sessions(self, email: str) -> list[str]:
        """Get all session IDs for a specific user.

        Args:
            email: User email address

        Returns:
            List of session IDs for the user
        """
        return [
            session_id
            for session_id, session in self.sessions.items()
            if session.get("email") == email
        ]

    def get_session_info(self, session_id: str) -> dict[str, Any] | None:
        """Get session information (safe for logging).

        Returns session data without sensitive information.

        Args:
            session_id: Session identifier

        Returns:
            Safe session information or None if not found
        """
        session = self.sessions.get(session_id)
        if not session:
            return None

        return {
            "email": session["email"],
            "is_admin": session["is_admin"],
            "user_tier": session["user_tier"],
            "created_at": session["created_at"].isoformat(),
            "last_accessed": session["last_accessed"].isoformat(),
            "age_seconds": (datetime.now() - session["created_at"]).total_seconds(),
        }

    def get_stats(self) -> dict[str, Any]:
        """Get session manager statistics.

        Returns:
            Dictionary with session statistics
        """
        now = datetime.now()
        active_sessions = []
        expired_sessions = []

        for session_id, session in self.sessions.items():
            if self._is_session_expired(session):
                expired_sessions.append(session_id)
            else:
                active_sessions.append(session_id)

        return {
            "total_sessions": len(self.sessions),
            "active_sessions": len(active_sessions),
            "expired_sessions": len(expired_sessions),
            "session_timeout": self.session_timeout,
            "sessions_by_tier": self._count_by_tier(),
        }

    def _count_by_tier(self) -> dict[str, int]:
        """Count sessions by user tier.

        Returns:
            Dictionary with tier counts
        """
        tier_counts: dict[str, int] = {"admin": 0, "full": 0, "limited": 0}

        for session in self.sessions.values():
            if not self._is_session_expired(session):
                tier = session.get("user_tier", "limited")
                if tier in tier_counts:
                    tier_counts[tier] += 1

        return tier_counts
