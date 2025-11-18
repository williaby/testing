"""Tests for Cloudflare authentication middleware.

This module provides example tests for the authentication system.
Expand these tests based on your specific requirements.
"""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch

from src.cloudflare_auth import CloudflareUser, setup_cloudflare_auth
from src.cloudflare_auth.middleware import get_current_user
from src.cloudflare_auth.models import CloudflareJWTClaims
from src.config.settings import CloudflareSettings


@pytest.fixture
def app():
    """Create a test FastAPI application."""
    app = FastAPI()

    @app.get("/public")
    async def public_endpoint():
        return {"message": "public"}

    @app.get("/protected")
    async def protected_endpoint(request: Request):
        user: CloudflareUser = request.state.user
        return {"email": user.email}

    return app


@pytest.fixture
def test_settings():
    """Create test settings."""
    return CloudflareSettings(
        cloudflare_team_domain="test.cloudflareaccess.com",
        cloudflare_audience_tag="test-audience",
        cloudflare_enabled=True,
    )


@pytest.fixture
def mock_claims():
    """Create mock JWT claims."""
    return CloudflareJWTClaims(
        email="test@example.com",
        iss="https://test.cloudflareaccess.com",
        aud=["test-audience"],
        sub="test-user-123",
        iat=1234567890,
        exp=9999999999,  # Far future
    )


@pytest.fixture
def mock_user(mock_claims):
    """Create a mock CloudflareUser."""
    return CloudflareUser.from_jwt_claims(mock_claims)


class TestCloudflareAuthMiddleware:
    """Test Cloudflare authentication middleware."""

    def test_public_endpoint_no_auth_required(self, app):
        """Test that public endpoints don't require authentication."""
        setup_cloudflare_auth(
            app,
            excluded_paths=["/public"],
            require_auth=True,
        )

        client = TestClient(app)
        response = client.get("/public")

        assert response.status_code == 200
        assert response.json() == {"message": "public"}

    def test_protected_endpoint_without_token(self, app, test_settings):
        """Test that protected endpoints reject requests without tokens."""
        with patch("src.config.settings.get_cloudflare_settings", return_value=test_settings):
            setup_cloudflare_auth(app, require_auth=True)

            client = TestClient(app)
            response = client.get("/protected")

            assert response.status_code == 401
            assert "authentication token" in response.json()["detail"].lower()

    def test_protected_endpoint_with_valid_token(
        self, app, test_settings, mock_claims, mock_user
    ):
        """Test that protected endpoints accept valid tokens."""
        with patch("src.config.settings.get_cloudflare_settings", return_value=test_settings):
            with patch(
                "src.cloudflare_auth.validators.CloudflareJWTValidator.validate_token",
                return_value=mock_claims,
            ):
                setup_cloudflare_auth(app, require_auth=True)

                client = TestClient(app)
                response = client.get(
                    "/protected",
                    headers={"Cf-Access-Jwt-Assertion": "valid-token"},
                )

                assert response.status_code == 200
                assert response.json()["email"] == "test@example.com"

    def test_disabled_authentication(self, app):
        """Test that authentication can be disabled for development."""
        settings = CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            cloudflare_audience_tag="test-audience",
            cloudflare_enabled=False,  # Disabled
        )

        with patch("src.config.settings.get_cloudflare_settings", return_value=settings):
            setup_cloudflare_auth(app, require_auth=False)

            client = TestClient(app)
            response = client.get("/public")

            assert response.status_code == 200


class TestCloudflareUser:
    """Test CloudflareUser model."""

    def test_user_creation_from_claims(self, mock_claims):
        """Test creating a user from JWT claims."""
        user = CloudflareUser.from_jwt_claims(mock_claims)

        assert user.email == "test@example.com"
        assert user.user_id == "test-user-123"
        assert user.claims == mock_claims

    def test_email_domain(self, mock_user):
        """Test email domain extraction."""
        assert mock_user.email_domain == "example.com"

    def test_email_username(self, mock_user):
        """Test email username extraction."""
        assert mock_user.email_username == "test"

    def test_has_email_domain(self, mock_user):
        """Test email domain checking."""
        assert mock_user.has_email_domain("example.com")
        assert not mock_user.has_email_domain("other.com")

    def test_model_dump_safe(self, mock_user):
        """Test safe model dumping without sensitive data."""
        safe_data = mock_user.model_dump_safe()

        assert "email" in safe_data
        assert "user_id" in safe_data
        assert "claims" not in safe_data


class TestCloudflareSettings:
    """Test Cloudflare settings."""

    def test_certs_url_generation(self):
        """Test certificate URL generation."""
        settings = CloudflareSettings(
            cloudflare_team_domain="myteam.cloudflareaccess.com",
            cloudflare_audience_tag="test",
        )

        assert settings.certs_url == "https://myteam.cloudflareaccess.com/cdn-cgi/access/certs"

    def test_issuer_generation(self):
        """Test issuer URL generation."""
        settings = CloudflareSettings(
            cloudflare_team_domain="myteam.cloudflareaccess.com",
            cloudflare_audience_tag="test",
        )

        assert settings.issuer == "https://myteam.cloudflareaccess.com"

    def test_email_domain_validation(self):
        """Test email domain validation."""
        settings = CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            cloudflare_audience_tag="test",
            allowed_email_domains=["example.com", "trusted.com"],
        )

        assert settings.is_email_allowed("user@example.com")
        assert settings.is_email_allowed("admin@trusted.com")
        assert not settings.is_email_allowed("user@untrusted.com")

    def test_no_email_restrictions(self):
        """Test that empty domain list allows all emails."""
        settings = CloudflareSettings(
            cloudflare_team_domain="test.cloudflareaccess.com",
            cloudflare_audience_tag="test",
            allowed_email_domains=[],
        )

        assert settings.is_email_allowed("user@anything.com")


# Example of how to run tests:
# pytest tests/test_middleware.py -v
