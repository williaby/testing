"""Utilities for secure logging and input sanitization.

This module provides utilities to prevent log injection and other
security issues related to logging user-controlled data.

Key Features:
    - Log injection prevention
    - Control character filtering
    - Configurable max length
    - Safe formatting for structured logging

Dependencies:
    - re: For pattern matching
    - typing: For type hints

Called by:
    - All middleware modules for safe logging
"""

import re
from typing import Any, Optional


# Patterns for dangerous characters in logs
CONTROL_CHARS_PATTERN = re.compile(r'[\x00-\x1f\x7f-\x9f]')
NEWLINE_PATTERN = re.compile(r'[\r\n]')


def sanitize_for_logging(
    value: Any,
    max_length: int = 200,
    replace_newlines: bool = True,
    replace_control_chars: bool = True,
) -> str:
    """Sanitize user input for safe logging.

    This function prevents log injection by:
    - Removing or replacing newline characters
    - Removing or replacing control characters
    - Truncating to maximum length
    - Converting to string safely

    Args:
        value: Value to sanitize (any type)
        max_length: Maximum length of output (default: 200)
        replace_newlines: Replace newlines with space (default: True)
        replace_control_chars: Replace control chars with � (default: True)

    Returns:
        Sanitized string safe for logging

    Example:
        >>> sanitize_for_logging("user@example.com\\nINJECTED LINE")
        'user@example.com INJECTED LINE'
        >>> sanitize_for_logging("x" * 300, max_length=100)
        'xxxx...xxxx (truncated)'
    """
    # Convert to string
    if value is None:
        return "None"

    try:
        str_value = str(value)
    except Exception:
        return "<non-printable>"

    # Remove/replace newlines to prevent log injection
    if replace_newlines:
        str_value = NEWLINE_PATTERN.sub(' ', str_value)

    # Remove/replace control characters
    if replace_control_chars:
        str_value = CONTROL_CHARS_PATTERN.sub('�', str_value)

    # Truncate if too long
    if len(str_value) > max_length:
        # Show beginning and end
        keep = (max_length - 20) // 2
        str_value = f"{str_value[:keep]}... (truncated) ...{str_value[-keep:]}"

    return str_value


def sanitize_email(email: str, max_length: int = 254) -> str:
    """Sanitize email address for logging.

    Validates email format and sanitizes for safe logging.

    Args:
        email: Email address to sanitize
        max_length: Maximum email length (default: 254 per RFC 5321)

    Returns:
        Sanitized email address

    Example:
        >>> sanitize_email("user@example.com")
        'user@example.com'
        >>> sanitize_email("malicious\\n@evil.com")
        'malicious @evil.com'
    """
    sanitized = sanitize_for_logging(email, max_length=max_length)

    # Ensure it still looks like an email
    if '@' not in sanitized:
        return "<invalid-email>"

    return sanitized


def sanitize_path(path: str, max_length: int = 200) -> str:
    """Sanitize URL path for logging.

    Args:
        path: URL path to sanitize
        max_length: Maximum path length

    Returns:
        Sanitized path

    Example:
        >>> sanitize_path("/api/users/123")
        '/api/users/123'
        >>> sanitize_path("/api\\n/etc/passwd")
        '/api /etc/passwd'
    """
    return sanitize_for_logging(path, max_length=max_length)


def sanitize_ip(ip: str, max_length: int = 45) -> str:
    """Sanitize IP address for logging.

    Args:
        ip: IP address to sanitize
        max_length: Maximum length (45 for IPv6)

    Returns:
        Sanitized IP address

    Example:
        >>> sanitize_ip("192.168.1.1")
        '192.168.1.1'
        >>> sanitize_ip("192.168.1.1\\nmalicious")
        '192.168.1.1 malicious'
    """
    sanitized = sanitize_for_logging(ip, max_length=max_length)

    # Basic IP format validation
    if not sanitized or sanitized == "unknown":
        return "unknown"

    # Remove any remaining suspicious characters
    # IPs should only contain digits, dots, colons (IPv6), and maybe brackets
    allowed_pattern = re.compile(r'^[0-9a-fA-F:.[\]]+$')
    if not allowed_pattern.match(sanitized):
        return "<invalid-ip>"

    return sanitized


def sanitize_dict_for_logging(
    data: dict[str, Any],
    max_value_length: int = 100,
    excluded_keys: Optional[set[str]] = None,
) -> dict[str, str]:
    """Sanitize dictionary for safe logging.

    Args:
        data: Dictionary to sanitize
        max_value_length: Maximum length for each value
        excluded_keys: Keys to exclude (e.g., 'password', 'token')

    Returns:
        Sanitized dictionary with string values

    Example:
        >>> sanitize_dict_for_logging({"email": "user@example.com", "password": "secret"}, excluded_keys={"password"})
        {'email': 'user@example.com', 'password': '<redacted>'}
    """
    if excluded_keys is None:
        excluded_keys = {
            'password', 'token', 'secret', 'key', 'api_key',
            'access_token', 'refresh_token', 'jwt', 'authorization'
        }

    sanitized = {}
    for key, value in data.items():
        # Check if key should be excluded
        key_lower = key.lower()
        if any(excluded in key_lower for excluded in excluded_keys):
            sanitized[key] = '<redacted>'
        else:
            sanitized[key] = sanitize_for_logging(value, max_length=max_value_length)

    return sanitized


def mask_sensitive_data(text: str, pattern: str = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b') -> str:
    """Mask sensitive data in text using regex pattern.

    Args:
        text: Text potentially containing sensitive data
        pattern: Regex pattern to match sensitive data (default: email pattern)

    Returns:
        Text with sensitive data masked

    Example:
        >>> mask_sensitive_data("Contact user@example.com for help")
        'Contact ***@***.*** for help'
    """
    def mask_match(match):
        matched = match.group(0)
        if '@' in matched:
            # Email-like pattern
            local, domain = matched.split('@', 1)
            return f"{'*' * min(len(local), 3)}@{'*' * min(len(domain), 3)}.***"
        return '*' * len(matched)

    return re.sub(pattern, mask_match, text)


def get_client_ip(request) -> str:
    """Extract client IP address from request.

    SECURITY NOTE: Only trusts CF-Connecting-IP header from Cloudflare.
    Other forwarding headers (X-Forwarded-For, X-Real-IP) are NOT trusted
    to prevent IP spoofing attacks. This assumes the application is behind
    Cloudflare Access.

    Args:
        request: FastAPI/Starlette Request object

    Returns:
        Client IP address string

    Example:
        >>> from fastapi import Request
        >>> ip = get_client_ip(request)
        >>> print(f"Client IP: {ip}")
    """
    # ONLY trust Cloudflare's CF-Connecting-IP header
    # This is set by Cloudflare and cannot be spoofed by clients
    cf_connecting_ip = request.headers.get("CF-Connecting-IP")
    if cf_connecting_ip:
        return cf_connecting_ip.strip()

    # Fall back to direct client IP if not behind Cloudflare
    # (e.g., development/testing environments)
    if request.client and request.client.host:
        return request.client.host

    return "unknown"
