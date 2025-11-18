# Package Migration Guide

This guide walks you through converting your Cloudflare authentication module into a reusable Python package that can be used across multiple projects while maintaining security testing separately.

---

## Table of Contents

1. [Package Structure](#package-structure)
2. [Restructuring the Code](#restructuring-the-code)
3. [Publishing the Package](#publishing-the-package)
4. [Using in Other Projects](#using-in-other-projects)
5. [Maintaining Security Testing](#maintaining-security-testing)
6. [Versioning Strategy](#versioning-strategy)
7. [CI/CD for the Package](#cicd-for-the-package)

---

## 1. Package Structure

### Recommended Structure

```
cloudflare-tunnel-auth/                 # Package repository
├── cloudflare_tunnel_auth/            # Main package (renamed from src/cloudflare_auth)
│   ├── __init__.py
│   ├── middleware.py
│   ├── middleware_enhanced.py
│   ├── validators.py
│   ├── models.py
│   ├── whitelist.py
│   ├── sessions.py
│   ├── redis_sessions.py
│   ├── rate_limiter.py
│   ├── csrf.py
│   ├── security_helpers.py
│   ├── utils.py
│   └── py.typed                       # Type stub marker
├── config/                            # Move from src/config
│   ├── __init__.py
│   └── settings.py
├── tests/                             # All tests stay here
│   ├── __init__.py
│   ├── test_middleware.py
│   ├── test_security_vulnerabilities.py
│   ├── test_validators.py
│   └── ...
├── examples/                          # Usage examples
│   ├── basic_usage.py
│   ├── advanced_usage.py
│   └── .env.example
├── docs/                              # Documentation
│   ├── CLOUDFLARE_TUNNEL_SECURITY_REVIEW.md
│   ├── SECURITY_HARDENING_GUIDE.md
│   └── ...
├── .github/                           # CI/CD workflows
│   └── workflows/
│       ├── test.yml
│       ├── security.yml
│       └── publish.yml
├── pyproject.toml                     # Package configuration (already created)
├── setup.py                           # Backward compatibility (already created)
├── README.md                          # Package README
├── CHANGELOG.md                       # Version history
├── LICENSE                            # MIT License
├── CONTRIBUTING.md                    # Contribution guidelines
├── SECURITY.md                        # Security policy
├── MANIFEST.in                        # Include non-Python files
└── .gitignore                         # Git ignore rules
```

---

## 2. Restructuring the Code

### Step 1: Reorganize Directory Structure

```bash
cd /home/user/testing

# Create new package structure
mkdir -p cloudflare_tunnel_auth
mkdir -p config
mkdir -p docs

# Move files from src/cloudflare_auth/ to cloudflare_tunnel_auth/
cp -r src/cloudflare_auth/* cloudflare_tunnel_auth/

# Move config
cp -r src/config/* config/

# Move documentation
mv CLOUDFLARE_TUNNEL_SECURITY_REVIEW.md docs/
mv SECURITY_HARDENING_GUIDE.md docs/
mv SECURITY_ANALYSIS.md docs/
mv SECURITY_FIXES.md docs/
mv SECURITY_BEST_PRACTICES.md docs/

# Keep tests/ as is (tests stay in package for security validation)
# Keep examples/ as is
```

### Step 2: Update Import Statements

The package uses relative imports, so you need to update:

**Before** (in your app):
```python
from src.cloudflare_auth import setup_cloudflare_auth
from src.config.settings import CloudflareSettings
```

**After** (in the package):
```python
# In cloudflare_tunnel_auth/__init__.py
from .middleware import setup_cloudflare_auth, get_current_user
from .middleware_enhanced import setup_cloudflare_auth_enhanced, require_admin
from .models import CloudflareUser, CloudflareJWTClaims
from .whitelist import UserTier, EmailWhitelistValidator

# Users of the package will import like:
from cloudflare_tunnel_auth import setup_cloudflare_auth, CloudflareUser
```

### Step 3: Create Package __init__.py

```python
# cloudflare_tunnel_auth/__init__.py
"""Cloudflare Tunnel Authentication Library.

Secure authentication for FastAPI applications behind Cloudflare Tunnel.
"""

__version__ = "1.0.0"

# Import main components for easy access
from .middleware import (
    CloudflareAuthMiddleware,
    setup_cloudflare_auth,
    get_current_user,
    get_current_user_optional,
)
from .middleware_enhanced import (
    CloudflareAuthMiddlewareEnhanced,
    setup_cloudflare_auth_enhanced,
    require_admin,
    require_tier,
)
from .models import CloudflareUser, CloudflareJWTClaims
from .whitelist import UserTier, EmailWhitelistValidator, WhitelistManager
from .validators import CloudflareJWTValidator
from .sessions import SimpleSessionManager
from .redis_sessions import RedisSessionManager
from .rate_limiter import InMemoryRateLimiter
from .csrf import CSRFProtection
from .security_helpers import SecurityHeadersMiddleware, AuditLogger

__all__ = [
    # Version
    "__version__",
    # Middleware
    "CloudflareAuthMiddleware",
    "CloudflareAuthMiddlewareEnhanced",
    "setup_cloudflare_auth",
    "setup_cloudflare_auth_enhanced",
    # Dependencies
    "get_current_user",
    "get_current_user_optional",
    "require_admin",
    "require_tier",
    # Models
    "CloudflareUser",
    "CloudflareJWTClaims",
    "UserTier",
    # Components
    "EmailWhitelistValidator",
    "WhitelistManager",
    "CloudflareJWTValidator",
    "SimpleSessionManager",
    "RedisSessionManager",
    "InMemoryRateLimiter",
    "CSRFProtection",
    "SecurityHeadersMiddleware",
    "AuditLogger",
]
```

### Step 4: Update Internal Imports

In each module file, update imports to use relative imports:

**Example in middleware.py**:
```python
# Before
from src.cloudflare_auth.models import CloudflareUser
from src.cloudflare_auth.validators import CloudflareJWTValidator
from src.config.settings import CloudflareSettings

# After
from .models import CloudflareUser
from .validators import CloudflareJWTValidator
from ..config.settings import CloudflareSettings  # Or make config part of package
```

**Better approach - include config in package**:
```python
# Move config into package
cloudflare_tunnel_auth/
├── __init__.py
├── middleware.py
├── config.py  # Rename from settings.py
└── ...

# Then import as:
from .config import CloudflareSettings
```

---

## 3. Publishing the Package

### Option A: Private Git Repository (Recommended to Start)

This allows you to use the package in other projects without public release.

```bash
# 1. Create new GitHub repository
# Go to https://github.com/new
# Name: cloudflare-tunnel-auth
# Private: Yes (or No if open source)

# 2. Initialize git (if not already)
cd /home/user/testing
git init
git add .
git commit -m "Initial package structure"

# 3. Push to GitHub
git remote add origin https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git
git branch -M main
git push -u origin main

# 4. Tag version
git tag v1.0.0
git push origin v1.0.0
```

**Using in other projects**:
```bash
# Install from GitHub
pip install git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git

# Or specific version
pip install git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0

# In requirements.txt
cloudflare-tunnel-auth @ git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0
```

### Option B: Private PyPI Server

For internal company use with pip install.

```bash
# 1. Set up devpi (private PyPI server)
pip install devpi-server devpi-client

# 2. Start server
devpi-server --start --host=localhost --port=3141

# 3. Create index
devpi use http://localhost:3141
devpi user -c yourname password=yourpass
devpi login yourname --password=yourpass
devpi index -c dev

# 4. Build and upload package
python -m build
devpi upload dist/*

# 5. Install from private PyPI
pip install --index-url http://localhost:3141/yourname/dev/ cloudflare-tunnel-auth
```

### Option C: Public PyPI (For Open Source)

```bash
# 1. Create account on https://pypi.org

# 2. Install build tools
pip install build twine

# 3. Build package
python -m build

# 4. Upload to PyPI
twine upload dist/*

# 5. Install from PyPI
pip install cloudflare-tunnel-auth
```

### Option D: Local Development (For Testing)

```bash
# Install in editable mode
cd cloudflare-tunnel-auth
pip install -e .

# Now changes to the package are immediately available
# No need to reinstall after each change
```

---

## 4. Using in Other Projects

### Project 1: Internal Dashboard

```bash
# Project structure
my-dashboard/
├── requirements.txt
├── .env
├── main.py
└── tests/
```

**requirements.txt**:
```txt
fastapi>=0.104.0
uvicorn>=0.24.0

# Install from private Git repo
cloudflare-tunnel-auth @ git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0

# Or from PyPI (if published)
# cloudflare-tunnel-auth==1.0.0
```

**main.py**:
```python
from fastapi import FastAPI, Depends
from cloudflare_tunnel_auth import (
    setup_cloudflare_auth_enhanced,
    CloudflareUser,
    get_current_user,
)

app = FastAPI()

# Configure auth with project-specific whitelist
setup_cloudflare_auth_enhanced(
    app,
    whitelist=["@mycompany.com"],
    admin_emails=["admin@mycompany.com"],
)

@app.get("/dashboard")
async def dashboard(user: CloudflareUser = Depends(get_current_user)):
    return {"user": user.email, "role": user.role}
```

**.env**:
```bash
CLOUDFLARE_TEAM_DOMAIN=mycompany.cloudflareaccess.com
CLOUDFLARE_AUDIENCE_TAG=dashboard-audience-tag
CLOUDFLARE_ENABLED=true
```

### Project 2: API Service

**requirements.txt**:
```txt
fastapi>=0.104.0
redis>=5.0.0  # For production sessions

cloudflare-tunnel-auth[redis] @ git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0
```

**main.py**:
```python
from fastapi import FastAPI, Depends
from cloudflare_tunnel_auth import (
    setup_cloudflare_auth_enhanced,
    RedisSessionManager,
    CloudflareUser,
    require_tier,
    UserTier,
)

app = FastAPI()

# Production setup with Redis
session_manager = RedisSessionManager(
    redis_url="redis://localhost:6379/0",
    session_timeout=7200,
)

setup_cloudflare_auth_enhanced(
    app,
    whitelist=["@mycompany.com", "@partner.com"],
    admin_emails=["devops@mycompany.com"],
    full_users=["@mycompany.com"],
    limited_users=["@partner.com"],
    enable_sessions=True,
)

# Create tier dependency
require_full = require_tier(UserTier.FULL)

@app.get("/api/premium")
async def premium_api(user: CloudflareUser = Depends(require_full)):
    return {"data": "premium content", "user": user.email}
```

### Project 3: Microservice

**main.py**:
```python
from fastapi import FastAPI
from cloudflare_tunnel_auth import setup_cloudflare_auth

app = FastAPI()

# Minimal setup - uses environment variables
setup_cloudflare_auth(app, require_auth=True)

@app.get("/service/data")
async def get_data(request: Request):
    user = request.state.user
    return {"service": "microservice-1", "user": user.email}
```

---

## 5. Maintaining Security Testing

### Keep Security Tests in Package

The security tests should stay **in the package repository** to ensure:
1. Every package version is security tested
2. Contributors can run tests before submitting changes
3. CI/CD validates security on each commit

### Package Repository Structure

```
cloudflare-tunnel-auth/
├── cloudflare_tunnel_auth/          # Package code
├── tests/
│   ├── test_middleware.py           # Unit tests
│   ├── test_security_vulnerabilities.py  # Security tests ← IMPORTANT
│   ├── test_validators.py
│   └── ...
├── .github/workflows/
│   ├── test.yml                     # Run all tests
│   ├── security.yml                 # Security scans
│   └── publish.yml                  # Publish on release
└── ...
```

### Security Testing Workflow

**.github/workflows/security.yml**:
```yaml
name: Security Testing

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Run daily at 2am
    - cron: '0 2 * * *'

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -e ".[test,security]"

      - name: Run security vulnerability tests
        run: |
          pytest tests/test_security_vulnerabilities.py -v --strict-markers

      - name: Run Bandit security scan
        run: |
          bandit -r cloudflare_tunnel_auth/ -ll

      - name: Run Safety dependency check
        run: |
          safety check --json

      - name: Fail on security issues
        run: |
          # Parse results and fail if critical/high issues found
          python scripts/check_security.py
```

### Running Security Tests Locally

```bash
# In package repository
cd cloudflare-tunnel-auth

# Install with test dependencies
pip install -e ".[test,security]"

# Run security tests
pytest tests/test_security_vulnerabilities.py -v

# Run security scans
bandit -r cloudflare_tunnel_auth/
safety check

# Run all tests
pytest
```

### In Consuming Projects

Projects using the package should also have their own tests:

```
my-project/
├── tests/
│   ├── test_app.py                  # App-specific tests
│   ├── test_auth_integration.py     # Integration tests with package
│   └── test_security_config.py      # Verify security configuration
└── ...
```

**test_auth_integration.py**:
```python
"""Integration tests for cloudflare-tunnel-auth package."""

import pytest
from fastapi.testclient import TestClient
from main import app


def test_auth_protects_routes():
    """Verify authentication protects routes."""
    client = TestClient(app)

    response = client.get("/protected")
    assert response.status_code == 401


def test_excluded_paths_work():
    """Verify health check doesn't require auth."""
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200


def test_whitelist_enforced():
    """Verify whitelist is properly configured."""
    # Test with your project's specific whitelist requirements
    pass
```

---

## 6. Versioning Strategy

### Semantic Versioning

Follow [SemVer](https://semver.org/):

- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
  - Changed function signatures
  - Removed features
  - Different behavior

- **MINOR** (1.0.0 → 1.1.0): New features (backward compatible)
  - New functions/classes
  - Optional parameters
  - New capabilities

- **PATCH** (1.0.0 → 1.0.1): Bug fixes
  - Security fixes
  - Bug corrections
  - Performance improvements

### Version Bumping Process

```bash
# 1. Make changes
git checkout -b feature/new-security-check

# 2. Update version in pyproject.toml
# version = "1.1.0"

# 3. Update CHANGELOG.md
# ## [1.1.0] - 2025-11-20
# ### Added
# - New security validation check
# ### Fixed
# - Bug in rate limiter

# 4. Commit and tag
git add .
git commit -m "Add new security validation check"
git tag v1.1.0

# 5. Push
git push origin feature/new-security-check
git push origin v1.1.0

# 6. Create pull request
# 7. After merge, publish new version
```

### CHANGELOG.md Example

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2025-11-20

### Added
- Additional Cloudflare header validation
- Support for custom session backends
- Documentation for advanced configuration

### Changed
- Improved error messages for authentication failures
- Enhanced logging with structured output

### Fixed
- Bug in rate limiter cleanup
- Timing issue in session expiration

### Security
- Fixed potential timing attack in email validation (CVE-2024-XXXXX)

## [1.0.0] - 2025-11-18

### Added
- Initial release
- JWT token validation
- Email whitelist with domain support
- User tier system
- Session management
- Rate limiting
- CSRF protection
- Comprehensive security testing

[Unreleased]: https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth/releases/tag/v1.0.0
```

---

## 7. CI/CD for the Package

### Complete GitHub Actions Workflow

**.github/workflows/test.yml**:
```yaml
name: Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ['3.9', '3.10', '3.11', '3.12']

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[test]"

      - name: Run tests
        run: |
          pytest --cov=cloudflare_tunnel_auth --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

**.github/workflows/publish.yml**:
```yaml
name: Publish to PyPI

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install build tools
        run: |
          pip install build twine

      - name: Build package
        run: |
          python -m build

      - name: Publish to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: |
          twine upload dist/*
```

---

## Summary: Complete Migration Checklist

### 1. Package Setup
- [ ] Create package structure (cloudflare_tunnel_auth/)
- [ ] Move files from src/ to package root
- [ ] Update all import statements
- [ ] Create proper __init__.py with exports
- [ ] Create pyproject.toml and setup.py
- [ ] Create README.md for package
- [ ] Create LICENSE file (MIT recommended)
- [ ] Create CHANGELOG.md

### 2. Security & Testing
- [ ] Move security tests to tests/ directory
- [ ] Create security.yml workflow
- [ ] Add Bandit and Safety to CI/CD
- [ ] Ensure all security tests pass
- [ ] Create test coverage reports

### 3. Documentation
- [ ] Move security docs to docs/ directory
- [ ] Create comprehensive README
- [ ] Add usage examples
- [ ] Create CONTRIBUTING.md
- [ ] Create SECURITY.md (security policy)

### 4. Repository Setup
- [ ] Create GitHub repository
- [ ] Push code to GitHub
- [ ] Tag initial version (v1.0.0)
- [ ] Set up branch protection
- [ ] Configure GitHub Actions

### 5. Publishing
- [ ] Choose publishing method (Git, PyPI, private)
- [ ] Build package (`python -m build`)
- [ ] Test installation in clean environment
- [ ] Publish to chosen platform
- [ ] Verify installation from platform

### 6. Usage in Projects
- [ ] Create example project
- [ ] Document integration steps
- [ ] Test in multiple projects
- [ ] Create troubleshooting guide

### 7. Maintenance
- [ ] Set up automated security scanning
- [ ] Create release process documentation
- [ ] Set up issue templates
- [ ] Create PR template
- [ ] Schedule regular security audits

---

## Next Steps

1. **Start with Option A** (Private Git Repository)
   - Easiest to set up
   - Works immediately
   - Can migrate to PyPI later

2. **Test in One Project First**
   - Install from Git
   - Verify all features work
   - Fix any issues

3. **Roll Out to Other Projects**
   - One project at a time
   - Document project-specific configurations
   - Gather feedback

4. **Consider PyPI Publication**
   - If stable and tested
   - If you want public open source
   - If you want easier pip install

---

## Support

For questions about package migration:
- Check the README.md in the package
- Review examples/ directory
- Open an issue on GitHub
- Review documentation in docs/
