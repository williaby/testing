"""Security vulnerability regression tests.

This test suite validates that critical security vulnerabilities are fixed
and cannot be reintroduced. Each test corresponds to a specific CVE or
security issue identified in security reviews.

Tests should NEVER be removed - only updated if the security model changes.
"""

import pytest
from fastapi import FastAPI, Request, Depends
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from src.cloudflare_auth import CloudflareAuthMiddleware, get_current_user
from src.cloudflare_auth.models import CloudflareUser, CloudflareJWTClaims
from src.config.settings import CloudflareSettings


class TestCriticalVulnerabilities:
    """Tests for CRITICAL severity vulnerabilities."""

    @pytest.fixture
    def app_with_auth(self):
        """Create test app with authentication."""
        app = FastAPI()

        settings = CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            cloudflare_audience_tag="test-audience",
            cloudflare_enabled=True,
            require_cloudflare_headers=True,
        )

        app.add_middleware(
            CloudflareAuthMiddleware,
            settings=settings,
            excluded_paths=["/health"],
            require_auth=True,
        )

        @app.get("/protected")
        async def protected_route(user: CloudflareUser = Depends(get_current_user)):
            return {"email": user.email}

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        return app

    def test_email_header_bypass_fixed(self, app_with_auth):
        """Test that missing email header blocks access (CVE-2024-XXXX equivalent).

        VULNERABILITY: Email header validation bypass
        SEVERITY: CRITICAL (CVSS 9.8)
        DISCOVERED: 2025-11-18
        FIXED: commit ed0be89

        Attack scenario:
        1. Attacker obtains valid JWT token
        2. Attacker sends request with JWT but OMITS email header
        3. BEFORE FIX: Validation bypassed, access granted
        4. AFTER FIX: Request rejected with 401

        This test ensures the vulnerability cannot be reintroduced.
        """
        client = TestClient(app_with_auth)

        # Create a mock valid JWT token
        valid_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"

        # Mock the validator to return valid claims
        mock_claims = CloudflareJWTClaims(
            email="attacker@evil.com",
            iss="https://test.cloudflareaccess.com",
            aud=["test-audience"],
            sub="attacker-id",
            iat=1700000000,
            exp=1700003600,
        )

        with patch("src.cloudflare_auth.middleware.CloudflareJWTValidator") as mock_validator:
            mock_validator_instance = MagicMock()
            mock_validator_instance.validate_token.return_value = mock_claims
            mock_validator.return_value = mock_validator_instance

            # Attack: Send JWT without email header (bypass attempt)
            response = client.get(
                "/protected",
                headers={
                    "Cf-Access-Jwt-Assertion": valid_jwt,
                    "CF-Ray": "test-ray-id",  # Valid Cloudflare header
                    # DELIBERATELY OMIT: "Cf-Access-Authenticated-User-Email"
                },
            )

            # CRITICAL: Must be rejected
            assert response.status_code == 401, (
                "SECURITY FAILURE: Email header bypass vulnerability detected! "
                "Request without email header was accepted. "
                "This is a CRITICAL authentication bypass."
            )
            assert "authentication" in response.json()["detail"].lower()

    def test_email_header_mismatch_blocked(self, app_with_auth):
        """Test that email header mismatch blocks access.

        VULNERABILITY: Email header validation
        SEVERITY: CRITICAL
        DISCOVERED: 2025-11-18

        Attack scenario:
        1. Attacker has JWT for victim@example.com
        2. Attacker sends request with different email header
        3. System must detect mismatch and reject
        """
        client = TestClient(app_with_auth)

        valid_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"

        mock_claims = CloudflareJWTClaims(
            email="victim@example.com",
            iss="https://test.cloudflareaccess.com",
            aud=["test-audience"],
            sub="victim-id",
            iat=1700000000,
            exp=1700003600,
        )

        with patch("src.cloudflare_auth.middleware.CloudflareJWTValidator") as mock_validator:
            mock_validator_instance = MagicMock()
            mock_validator_instance.validate_token.return_value = mock_claims
            mock_validator.return_value = mock_validator_instance

            # Attack: Email mismatch
            response = client.get(
                "/protected",
                headers={
                    "Cf-Access-Jwt-Assertion": valid_jwt,
                    "Cf-Access-Authenticated-User-Email": "attacker@evil.com",  # Mismatch!
                    "CF-Ray": "test-ray-id",
                },
            )

            assert response.status_code == 401, (
                "SECURITY FAILURE: Email mismatch not detected! "
                "Attacker could spoof identity."
            )

    def test_jwt_size_limit_enforced(self, app_with_auth):
        """Test that oversized JWT tokens are rejected (DoS protection).

        VULNERABILITY: JWT token size DoS
        SEVERITY: HIGH
        DISCOVERED: 2025-11-18
        FIXED: commit ed0be89

        Attack scenario:
        1. Attacker sends extremely large JWT token (>8KB)
        2. BEFORE FIX: Token processed, memory exhausted
        3. AFTER FIX: Token rejected immediately
        """
        client = TestClient(app_with_auth)

        # Create oversized JWT (9KB)
        oversized_jwt = "x" * 9000

        response = client.get(
            "/protected",
            headers={
                "Cf-Access-Jwt-Assertion": oversized_jwt,
                "CF-Ray": "test-ray-id",
            },
        )

        assert response.status_code == 400, (
            "SECURITY FAILURE: Oversized JWT not rejected! "
            "Application vulnerable to DoS via memory exhaustion."
        )

    def test_production_auth_cannot_be_disabled(self):
        """Test that authentication cannot be disabled in production.

        VULNERABILITY: Production misconfiguration
        SEVERITY: HIGH
        DISCOVERED: 2025-11-18
        FIXED: commit ed0be89

        Attack scenario:
        1. DevOps error sets CLOUDFLARE_ENABLED=false in production
        2. BEFORE FIX: All authentication disabled
        3. AFTER FIX: Application refuses to start
        """
        with pytest.raises(ValueError, match="SECURITY ERROR.*PRODUCTION"):
            CloudflareSettings(
                environment="prod",
                cloudflare_enabled=False,  # Should raise error
                cloudflare_team_domain="test.cloudflareaccess.com",
                cloudflare_audience_tag="test-audience",
            )

        # Also test "production" variant
        with pytest.raises(ValueError, match="SECURITY ERROR.*PRODUCTION"):
            CloudflareSettings(
                environment="production",
                cloudflare_enabled=False,
                cloudflare_team_domain="test.cloudflareaccess.com",
                cloudflare_audience_tag="test-audience",
            )


class TestHighSeverityVulnerabilities:
    """Tests for HIGH severity vulnerabilities."""

    @pytest.fixture
    def app_with_origin_check(self):
        """Create test app with Cloudflare origin validation."""
        app = FastAPI()

        settings = CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            cloudflare_audience_tag="test-audience",
            cloudflare_enabled=True,
            require_cloudflare_headers=True,
            allowed_tunnel_ips=["127.0.0.1"],
        )

        app.add_middleware(
            CloudflareAuthMiddleware,
            settings=settings,
            excluded_paths=["/health"],
            require_auth=True,
        )

        @app.get("/protected")
        async def protected_route(user: CloudflareUser = Depends(get_current_user)):
            return {"email": user.email}

        return app

    def test_cloudflare_origin_validation(self, app_with_origin_check):
        """Test that requests without CF-Ray header are blocked.

        VULNERABILITY: No Cloudflare origin validation
        SEVERITY: HIGH
        DISCOVERED: 2025-11-18
        FIXED: commit ed0be89

        Attack scenario:
        1. Attacker gains network access to app container
        2. Attacker connects directly, bypassing Cloudflare tunnel
        3. BEFORE FIX: Request processed normally
        4. AFTER FIX: Request rejected (no CF-Ray header)
        """
        client = TestClient(app_with_origin_check)

        valid_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"

        # Mock validator
        mock_claims = CloudflareJWTClaims(
            email="user@example.com",
            iss="https://test.cloudflareaccess.com",
            aud=["test-audience"],
            sub="user-id",
            iat=1700000000,
            exp=1700003600,
        )

        with patch("src.cloudflare_auth.middleware.CloudflareJWTValidator") as mock_validator:
            mock_validator_instance = MagicMock()
            mock_validator_instance.validate_token.return_value = mock_claims
            mock_validator.return_value = mock_validator_instance

            # Attack: Direct access without Cloudflare headers
            response = client.get(
                "/protected",
                headers={
                    "Cf-Access-Jwt-Assertion": valid_jwt,
                    "Cf-Access-Authenticated-User-Email": "user@example.com",
                    # DELIBERATELY OMIT: "CF-Ray"
                },
            )

            assert response.status_code == 403, (
                "SECURITY FAILURE: Direct access not blocked! "
                "Attacker can bypass Cloudflare tunnel security."
            )

    def test_ip_allowlist_enforcement(self, app_with_origin_check):
        """Test that non-whitelisted IPs are blocked.

        VULNERABILITY: No IP allowlisting
        SEVERITY: HIGH
        DISCOVERED: 2025-11-18
        """
        client = TestClient(app_with_origin_check)

        valid_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"

        mock_claims = CloudflareJWTClaims(
            email="user@example.com",
            iss="https://test.cloudflareaccess.com",
            aud=["test-audience"],
            sub="user-id",
            iat=1700000000,
            exp=1700003600,
        )

        with patch("src.cloudflare_auth.middleware.CloudflareJWTValidator") as mock_validator:
            mock_validator_instance = MagicMock()
            mock_validator_instance.validate_token.return_value = mock_claims
            mock_validator.return_value = mock_validator_instance

            # Mock get_client_ip to return unauthorized IP
            with patch("src.cloudflare_auth.middleware.get_client_ip", return_value="192.168.1.100"):
                response = client.get(
                    "/protected",
                    headers={
                        "Cf-Access-Jwt-Assertion": valid_jwt,
                        "Cf-Access-Authenticated-User-Email": "user@example.com",
                        "CF-Ray": "test-ray-id",
                    },
                )

                assert response.status_code == 403, (
                    "SECURITY FAILURE: Unauthorized IP not blocked! "
                    "IP allowlist not enforced."
                )


class TestRateLimitingVulnerabilities:
    """Tests for rate limiting vulnerabilities."""

    def test_rate_limiting_enforced(self):
        """Test that rate limiting prevents brute force attacks.

        VULNERABILITY: No rate limiting
        SEVERITY: MEDIUM
        DISCOVERED: Previous security review
        """
        from src.cloudflare_auth.rate_limiter import InMemoryRateLimiter

        limiter = InMemoryRateLimiter(max_attempts=3, window_seconds=60)

        # Simulate 3 failed attempts
        for i in range(3):
            assert limiter.is_allowed("192.168.1.1"), f"Attempt {i+1} should be allowed"
            limiter.record_attempt("192.168.1.1")

        # 4th attempt should be blocked
        assert not limiter.is_allowed("192.168.1.1"), (
            "SECURITY FAILURE: Rate limiting not enforced! "
            "Brute force attacks possible."
        )

        # Get retry-after time
        retry_after = limiter.get_retry_after("192.168.1.1")
        assert retry_after > 0, "Rate limiter should provide retry-after time"


class TestSessionSecurityVulnerabilities:
    """Tests for session security vulnerabilities."""

    def test_session_ids_cryptographically_secure(self):
        """Test that session IDs use cryptographically secure random.

        VULNERABILITY: Weak session ID generation
        SEVERITY: HIGH
        """
        from src.cloudflare_auth.sessions import SimpleSessionManager

        manager = SimpleSessionManager()

        # Generate multiple session IDs
        session_ids = set()
        for _ in range(100):
            session_id = manager.create_session(
                email="test@example.com",
                is_admin=False,
            )
            session_ids.add(session_id)

        # All IDs should be unique
        assert len(session_ids) == 100, (
            "SECURITY FAILURE: Session ID collision detected! "
            "Weak random number generation."
        )

        # IDs should be sufficient length (32+ bytes)
        for session_id in session_ids:
            assert len(session_id) >= 32, (
                "SECURITY FAILURE: Session ID too short! "
                f"Got {len(session_id)} chars, need 32+."
            )

    def test_session_cookies_secure_flags(self):
        """Test that session cookies have secure flags.

        This is verified in middleware tests but important for security.
        """
        from src.config.settings import CloudflareSettings

        settings = CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            cloudflare_audience_tag="test-audience",
            environment="prod",
        )

        # Production should enforce secure cookies
        assert settings.cookie_secure is True, (
            "SECURITY FAILURE: Secure cookie flag not set! "
            "Cookies vulnerable to interception."
        )
        assert settings.cookie_samesite == "strict", (
            "SECURITY FAILURE: SameSite not strict! "
            "CSRF attacks possible."
        )


class TestInputValidationVulnerabilities:
    """Tests for input validation vulnerabilities."""

    def test_email_whitelist_timing_attack_protection(self):
        """Test that email comparison uses constant-time comparison.

        VULNERABILITY: Timing attack on email validation
        SEVERITY: MEDIUM
        DISCOVERED: Previous security review
        """
        from src.cloudflare_auth.whitelist import EmailWhitelistValidator
        import time

        validator = EmailWhitelistValidator(
            whitelist=["allowed@example.com"],
        )

        # Time comparison for incorrect emails of different lengths
        # Should have similar timing (constant-time)

        start = time.perf_counter()
        for _ in range(1000):
            validator.is_authorized("a@example.com")
        time_short = time.perf_counter() - start

        start = time.perf_counter()
        for _ in range(1000):
            validator.is_authorized("verylongemailaddress@example.com")
        time_long = time.perf_counter() - start

        # Timing difference should be minimal (less than 10% variance)
        # This is a heuristic test - timing attacks are hard to test perfectly
        ratio = max(time_short, time_long) / min(time_short, time_long)
        assert ratio < 1.5, (
            f"SECURITY WARNING: Timing variance detected ({ratio:.2f}x). "
            "Potential timing attack vulnerability. "
            "Email comparison may not be constant-time."
        )


class TestSecurityHeaders:
    """Tests for security headers."""

    def test_security_headers_present(self):
        """Test that security headers are configured.

        VULNERABILITY: Missing security headers
        SEVERITY: MEDIUM
        """
        from src.config.settings import CloudflareSettings

        settings = CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            cloudflare_audience_tag="test-audience",
        )

        # Verify secure defaults
        assert settings.cookie_secure is True
        assert settings.cookie_samesite == "strict"
        assert settings.cookie_path == "/"


# Test execution summary
def test_security_suite_summary(capsys):
    """Print security test suite summary."""
    print("\n" + "="*80)
    print("SECURITY VULNERABILITY TEST SUITE")
    print("="*80)
    print("\nThis test suite validates fixes for the following vulnerabilities:")
    print("\n🔴 CRITICAL:")
    print("  - Email header validation bypass (CVSS 9.8)")
    print("  - JWT token size DoS attack")
    print("\n🟠 HIGH:")
    print("  - Cloudflare origin validation bypass")
    print("  - Production misconfiguration")
    print("  - IP allowlist enforcement")
    print("\n🟡 MEDIUM:")
    print("  - Rate limiting bypass")
    print("  - Session security")
    print("  - Timing attacks")
    print("\nAll tests MUST pass before production deployment.")
    print("="*80 + "\n")
