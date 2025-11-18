"""Rate limiting utilities for authentication endpoints.

This module provides in-memory rate limiting to protect against brute force
and DoS attacks on authentication endpoints.

Key Features:
    - IP-based rate limiting
    - Configurable limits and time windows
    - Automatic cleanup of expired entries
    - Thread-safe implementation

Note:
    For production with multiple instances, use a distributed rate limiter
    like Redis-based slowapi or similar solutions.

Dependencies:
    - threading: For thread-safe operations
    - datetime: For time-based limiting

Called by:
    - src.cloudflare_auth.middleware: For authentication rate limiting
"""

from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, Tuple
import logging

logger = logging.getLogger(__name__)


class InMemoryRateLimiter:
    """In-memory rate limiter for authentication attempts.

    This rate limiter tracks authentication attempts per IP address and
    enforces configurable limits to prevent brute force attacks.

    Note:
        This is an in-memory implementation suitable for single-instance
        deployments. For production with multiple instances, use Redis
        or similar distributed solutions.

    Example:
        limiter = InMemoryRateLimiter(
            max_attempts=5,
            window_seconds=60
        )

        if not limiter.is_allowed(client_ip):
            raise HTTPException(status_code=429, detail="Too many requests")

        # Process authentication...
        limiter.record_attempt(client_ip)
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 60,
        cleanup_interval: int = 300,
    ) -> None:
        """Initialize rate limiter.

        Args:
            max_attempts: Maximum attempts allowed within window
            window_seconds: Time window in seconds
            cleanup_interval: Seconds between cleanup operations
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval

        # Store: IP -> list of attempt timestamps
        self.attempts: Dict[str, list[datetime]] = defaultdict(list)
        self.lock = Lock()
        self.last_cleanup = datetime.now()

        logger.info(
            "Initialized rate limiter: %d attempts per %d seconds",
            max_attempts,
            window_seconds,
        )

    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed based on rate limit.

        Args:
            identifier: IP address or other identifier

        Returns:
            True if request is allowed, False if rate limited
        """
        with self.lock:
            self._cleanup_if_needed()

            current_time = datetime.now()
            cutoff_time = current_time - timedelta(seconds=self.window_seconds)

            # Get attempts within window
            if identifier in self.attempts:
                # Remove expired attempts
                self.attempts[identifier] = [
                    timestamp for timestamp in self.attempts[identifier]
                    if timestamp > cutoff_time
                ]

                # Check if limit exceeded
                if len(self.attempts[identifier]) >= self.max_attempts:
                    logger.warning(
                        "Rate limit exceeded for %s: %d attempts in %d seconds",
                        identifier,
                        len(self.attempts[identifier]),
                        self.window_seconds,
                    )
                    return False

            return True

    def record_attempt(self, identifier: str) -> None:
        """Record an authentication attempt.

        Args:
            identifier: IP address or other identifier
        """
        with self.lock:
            self.attempts[identifier].append(datetime.now())

    def reset(self, identifier: str) -> None:
        """Reset rate limit for an identifier.

        Args:
            identifier: IP address or other identifier
        """
        with self.lock:
            if identifier in self.attempts:
                del self.attempts[identifier]
                logger.debug("Reset rate limit for %s", identifier)

    def get_remaining_attempts(self, identifier: str) -> int:
        """Get remaining attempts for an identifier.

        Args:
            identifier: IP address or other identifier

        Returns:
            Number of remaining attempts
        """
        with self.lock:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(seconds=self.window_seconds)

            if identifier not in self.attempts:
                return self.max_attempts

            # Count recent attempts
            recent_attempts = [
                timestamp for timestamp in self.attempts[identifier]
                if timestamp > cutoff_time
            ]

            return max(0, self.max_attempts - len(recent_attempts))

    def get_retry_after(self, identifier: str) -> int:
        """Get seconds until identifier can retry.

        Args:
            identifier: IP address or other identifier

        Returns:
            Seconds until next attempt is allowed (0 if allowed now)
        """
        with self.lock:
            if identifier not in self.attempts or not self.attempts[identifier]:
                return 0

            current_time = datetime.now()
            cutoff_time = current_time - timedelta(seconds=self.window_seconds)

            # Find oldest attempt in window
            recent_attempts = [
                timestamp for timestamp in self.attempts[identifier]
                if timestamp > cutoff_time
            ]

            if len(recent_attempts) < self.max_attempts:
                return 0

            # Calculate when oldest attempt will expire
            oldest_attempt = min(recent_attempts)
            retry_time = oldest_attempt + timedelta(seconds=self.window_seconds)
            wait_seconds = (retry_time - current_time).total_seconds()

            return max(0, int(wait_seconds))

    def _cleanup_if_needed(self) -> None:
        """Clean up expired entries if interval has passed.

        Note: Must be called while holding self.lock
        """
        current_time = datetime.now()
        if (current_time - self.last_cleanup).total_seconds() < self.cleanup_interval:
            return

        # Remove expired entries
        cutoff_time = current_time - timedelta(seconds=self.window_seconds)
        identifiers_to_remove = []

        for identifier, timestamps in self.attempts.items():
            # Remove old timestamps
            self.attempts[identifier] = [
                ts for ts in timestamps if ts > cutoff_time
            ]

            # Mark empty entries for removal
            if not self.attempts[identifier]:
                identifiers_to_remove.append(identifier)

        # Remove empty entries
        for identifier in identifiers_to_remove:
            del self.attempts[identifier]

        self.last_cleanup = current_time

        if identifiers_to_remove:
            logger.debug(
                "Cleaned up %d expired rate limit entries",
                len(identifiers_to_remove)
            )

    def get_stats(self) -> dict:
        """Get rate limiter statistics.

        Returns:
            Dictionary with current statistics
        """
        with self.lock:
            total_tracked = len(self.attempts)
            total_attempts = sum(len(timestamps) for timestamps in self.attempts.values())

            return {
                "tracked_identifiers": total_tracked,
                "total_attempts": total_attempts,
                "max_attempts": self.max_attempts,
                "window_seconds": self.window_seconds,
                "last_cleanup": self.last_cleanup.isoformat(),
            }


# Global rate limiter instance
_global_rate_limiter: InMemoryRateLimiter | None = None


def get_rate_limiter(
    max_attempts: int = 5,
    window_seconds: int = 60,
) -> InMemoryRateLimiter:
    """Get or create global rate limiter instance.

    Args:
        max_attempts: Maximum attempts per window
        window_seconds: Time window in seconds

    Returns:
        InMemoryRateLimiter instance
    """
    global _global_rate_limiter

    if _global_rate_limiter is None:
        _global_rate_limiter = InMemoryRateLimiter(
            max_attempts=max_attempts,
            window_seconds=window_seconds,
        )

    return _global_rate_limiter
