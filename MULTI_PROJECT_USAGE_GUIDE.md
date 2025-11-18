# Multi-Project Usage Guide

**Complete guide for converting this authentication module into a reusable package for use across multiple projects**

---

## Quick Start Summary

This guide shows you how to:
1. ✅ Convert your code into a Python package
2. ✅ Maintain it separately with security testing
3. ✅ Use it across multiple projects
4. ✅ Keep it updated and secure

**Python Compatibility**: Python 3.10 through 3.14

---

## 🎯 Three Ways to Use Across Projects

### Option 1: Private Git Repository (Recommended) ⭐

**Best for**: Internal company projects, teams using GitHub

**Setup Time**: 10 minutes

**Advantages**:
- ✅ Free
- ✅ Works immediately
- ✅ Version control built-in
- ✅ Easy team collaboration
- ✅ Can make public later

**Steps**:

```bash
# 1. Create GitHub repository
# Go to: https://github.com/new
# Name: cloudflare-tunnel-auth
# Private: Yes (or No for open source)

# 2. Push your code
cd /home/user/testing
git remote add origin https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git
git push -u origin main

# 3. Tag a version
git tag v1.0.0
git push origin v1.0.0

# Done! Now you can use it in any project:
pip install git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0
```

**Using in your projects**:

```txt
# requirements.txt
fastapi>=0.104.0
cloudflare-tunnel-auth @ git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0
```

```python
# main.py
from fastapi import FastAPI
from cloudflare_tunnel_auth import setup_cloudflare_auth, CloudflareUser

app = FastAPI()
setup_cloudflare_auth(app)
```

---

### Option 2: Local Path Install (Development)

**Best for**: Testing, development, single machine

**Setup Time**: 1 minute

**Steps**:

```bash
# Install in editable mode
cd /home/user/testing
pip install -e .

# Now use in any project on this machine
```

**Note**: Changes to the package code are immediately available (no reinstall needed)

---

### Option 3: PyPI Package (Public/Private)

**Best for**: Open source, wide distribution, pip install

**Setup Time**: 30 minutes

**Steps**:

```bash
# 1. Create account on https://pypi.org

# 2. Install build tools
pip install build twine

# 3. Build package
python -m build

# 4. Upload
twine upload dist/*

# Done! Now anyone can:
pip install cloudflare-tunnel-auth
```

---

## 📦 Package Structure (Already Set Up!)

You have two options for package structure:

### Option A: Keep Current Structure

```
testing/                              # Your current repo
├── src/cloudflare_auth/             # Your code (rename to cloudflare_tunnel_auth)
├── src/config/
├── tests/
├── examples/
├── pyproject.toml                   # ✅ Already created
├── setup.py                         # ✅ Already created
└── README_PACKAGE.md                # ✅ Already created
```

**To use**: Just rename `src/cloudflare_auth` to `cloudflare_tunnel_auth` and you're done!

```bash
cd /home/user/testing
mv src/cloudflare_auth cloudflare_tunnel_auth
# Update imports in code (see below)
```

### Option B: Clean Package Structure

```
cloudflare-tunnel-auth/              # New clean repo (recommended for public release)
├── cloudflare_tunnel_auth/         # Package code
│   ├── __init__.py
│   ├── middleware.py
│   ├── validators.py
│   ├── models.py
│   ├── whitelist.py
│   ├── sessions.py
│   ├── config.py                   # Merged from src/config/settings.py
│   └── ...
├── tests/
├── examples/
├── docs/
├── pyproject.toml
└── README.md
```

---

## 🔧 Quick Conversion (5 Minutes)

### Step 1: Rename Package Directory

```bash
cd /home/user/testing

# Rename main package
mv src/cloudflare_auth cloudflare_tunnel_auth

# Move config into package (simplifies imports)
cp src/config/settings.py cloudflare_tunnel_auth/config.py

# Update package __init__.py
```

### Step 2: Update Imports

**File**: `cloudflare_tunnel_auth/__init__.py`

```python
"""Cloudflare Tunnel Authentication Library."""

__version__ = "1.0.0"

# Main components
from .middleware import (
    setup_cloudflare_auth,
    get_current_user,
    CloudflareAuthMiddleware,
)
from .middleware_enhanced import (
    setup_cloudflare_auth_enhanced,
    require_admin,
    require_tier,
)
from .models import CloudflareUser, UserTier
from .sessions import SimpleSessionManager
from .redis_sessions import RedisSessionManager

__all__ = [
    "__version__",
    "setup_cloudflare_auth",
    "setup_cloudflare_auth_enhanced",
    "get_current_user",
    "require_admin",
    "require_tier",
    "CloudflareUser",
    "UserTier",
    "CloudflareAuthMiddleware",
    "SimpleSessionManager",
    "RedisSessionManager",
]
```

### Step 3: Update Internal Imports

In each file within `cloudflare_tunnel_auth/`, change:

```python
# Before:
from src.cloudflare_auth.models import CloudflareUser
from src.config.settings import CloudflareSettings

# After:
from .models import CloudflareUser
from .config import CloudflareSettings
```

### Step 4: Test the Package

```bash
# Install locally
pip install -e .

# Run tests
pytest tests/

# Run security tests
pytest tests/test_security_vulnerabilities.py -v
```

---

## 🚀 Using in Multiple Projects

### Project 1: Internal Dashboard

```
dashboard-app/
├── requirements.txt
├── .env
├── main.py
└── config.py
```

**requirements.txt**:
```txt
fastapi>=0.104.0
uvicorn>=0.24.0
cloudflare-tunnel-auth @ git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0
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

# Setup with project-specific config
setup_cloudflare_auth_enhanced(
    app,
    whitelist=["@mycompany.com"],
    admin_emails=["admin@mycompany.com"],
)

@app.get("/dashboard")
async def dashboard(user: CloudflareUser = Depends(get_current_user)):
    return {
        "user": user.email,
        "tier": user.user_tier.value,
        "is_admin": user.is_admin,
    }
```

**.env**:
```bash
CLOUDFLARE_TEAM_DOMAIN=mycompany.cloudflareaccess.com
CLOUDFLARE_AUDIENCE_TAG=dashboard-app-audience-tag
```

### Project 2: API Service

**requirements.txt**:
```txt
fastapi>=0.104.0
redis>=5.0.0
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

# Production setup with Redis sessions
session_manager = RedisSessionManager(
    redis_url="redis://redis:6379/0",
    session_timeout=3600,
)

setup_cloudflare_auth_enhanced(
    app,
    whitelist=["@mycompany.com", "@partner.com"],
    admin_emails=["devops@mycompany.com"],
    full_users=["@mycompany.com"],
    limited_users=["@partner.com"],
)

# Only allow full-tier users
require_full = require_tier(UserTier.FULL)

@app.get("/api/premium")
async def premium_api(user: CloudflareUser = Depends(require_full)):
    return {"data": "premium content"}
```

### Project 3: Microservice

**requirements.txt**:
```txt
fastapi>=0.104.0
cloudflare-tunnel-auth @ git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0
```

**main.py**:
```python
from fastapi import FastAPI, Request
from cloudflare_tunnel_auth import setup_cloudflare_auth

app = FastAPI()

# Minimal setup - uses environment variables
setup_cloudflare_auth(app)

@app.get("/service/data")
async def get_data(request: Request):
    user = request.state.user
    return {"service": "microservice", "user": user.email}
```

---

## 🔒 Maintaining Security Testing

### Security Tests Stay in Package Repository

**Why?** Security tests ensure:
- Every version is security tested before release
- Contributors can validate changes
- Automated CI/CD catches vulnerabilities
- Compliance requirements are met

### Package Repository Structure

```
cloudflare-tunnel-auth/
├── cloudflare_tunnel_auth/         # Package code
├── tests/
│   ├── test_middleware.py
│   ├── test_security_vulnerabilities.py  # ← Security tests stay here!
│   └── ...
├── .github/workflows/
│   ├── test.yml                    # Tests all Python versions
│   └── security.yml                # Security scans
└── ...
```

### CI/CD Security Testing

**File**: `.github/workflows/test.yml` (Already created!)

This workflow:
- ✅ Tests Python 3.10, 3.11, 3.12, 3.13, 3.14-dev
- ✅ Runs on Ubuntu, macOS, Windows
- ✅ Runs security vulnerability tests
- ✅ Runs Bandit security scanner
- ✅ Runs Safety dependency checker
- ✅ Uploads coverage reports

**To enable**:
1. Push code to GitHub
2. GitHub Actions automatically runs
3. All tests must pass before merge

### Running Security Tests Locally

```bash
# In package repository
cd cloudflare-tunnel-auth

# Install with security tools
pip install -e ".[test,security]"

# Run all security tests
pytest tests/test_security_vulnerabilities.py -v

# Run security scanners
bandit -r cloudflare_tunnel_auth/ -ll
safety check
```

---

## 📝 Version Management

### Semantic Versioning

Use [SemVer](https://semver.org/) for versions:

- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
- **MINOR** (1.0.0 → 1.1.0): New features (backward compatible)
- **PATCH** (1.0.0 → 1.0.1): Bug fixes

### Releasing a New Version

```bash
# 1. Make changes and test
git checkout -b feature/new-feature
# ... make changes ...
pytest tests/

# 2. Update version in pyproject.toml
# version = "1.1.0"

# 3. Update CHANGELOG.md
# ## [1.1.0] - 2025-11-20
# ### Added
# - New feature X

# 4. Commit and tag
git add .
git commit -m "Add feature X"
git tag v1.1.0

# 5. Push
git push origin feature/new-feature
git push origin v1.1.0

# 6. Projects can now use:
# cloudflare-tunnel-auth @ git+https://...@v1.1.0
```

### Updating in Projects

When new version is released:

```bash
# In your project
cd dashboard-app

# Update requirements.txt with new version
# cloudflare-tunnel-auth @ git+https://...@v1.1.0

# Reinstall
pip install --upgrade -r requirements.txt

# Test your app
pytest
```

---

## 🧪 Python Version Compatibility

### Supported Versions

✅ **Python 3.10** (2021)
✅ **Python 3.11** (2022)
✅ **Python 3.12** (2023)
✅ **Python 3.13** (2024)
✅ **Python 3.14** (2025 - when released)

### Testing All Versions

GitHub Actions automatically tests all versions:

```yaml
# .github/workflows/test.yml
strategy:
  matrix:
    python-version: ['3.10', '3.11', '3.12', '3.13']
    include:
      - python-version: '3.14-dev'  # Pre-release
```

### Local Testing

```bash
# Using pyenv to test multiple versions
pyenv install 3.10.13
pyenv install 3.11.7
pyenv install 3.12.1
pyenv install 3.13.0

# Test each version
for version in 3.10.13 3.11.7 3.12.1 3.13.0; do
  pyenv shell $version
  pip install -e ".[test]"
  pytest
done
```

### Compatibility Notes

**Python 3.10+**: Uses modern Python features:
- Structural pattern matching (match/case)
- Type union operator (X | Y)
- Parenthesized context managers
- Better error messages

**Dependencies**:
- All dependencies support Python 3.10+
- FastAPI, Pydantic, PyJWT fully compatible
- Type hints use modern syntax

---

## 📚 Complete Example Workflow

### Initial Setup

```bash
# 1. Create GitHub repository
# https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth

# 2. Clone your current code
cd /home/user/testing

# 3. Rename package
mv src/cloudflare_auth cloudflare_tunnel_auth

# 4. Update imports (see Step 2-3 above)

# 5. Test locally
pip install -e .
pytest tests/

# 6. Push to GitHub
git remote add origin https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git
git push -u origin main
git tag v1.0.0
git push origin v1.0.0
```

### Use in Project 1

```bash
# Create new project
mkdir dashboard-app
cd dashboard-app

# Create requirements.txt
cat > requirements.txt << 'EOF'
fastapi>=0.104.0
uvicorn>=0.24.0
cloudflare-tunnel-auth @ git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0
EOF

# Install
pip install -r requirements.txt

# Create app
cat > main.py << 'EOF'
from fastapi import FastAPI, Depends
from cloudflare_tunnel_auth import setup_cloudflare_auth, CloudflareUser, get_current_user

app = FastAPI()
setup_cloudflare_auth(app)

@app.get("/")
async def root(user: CloudflareUser = Depends(get_current_user)):
    return {"user": user.email}
EOF

# Run
uvicorn main:app --reload
```

### Use in Project 2

```bash
# Create another project
mkdir api-service
cd api-service

# Same requirements
pip install cloudflare-tunnel-auth @ git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0

# Different configuration
# ... customize for your needs
```

---

## ✅ Benefits of This Approach

### 1. Separation of Concerns
- ✅ Auth logic in one place
- ✅ Projects import as dependency
- ✅ Easy to update across all projects

### 2. Security
- ✅ Security tests run on every change
- ✅ Automated vulnerability scanning
- ✅ Version control for security fixes

### 3. Maintenance
- ✅ Fix bug once, update all projects
- ✅ Clear version history
- ✅ Easy rollback if needed

### 4. Testing
- ✅ Comprehensive test suite
- ✅ Tests across Python versions
- ✅ Tests on multiple OS platforms

### 5. Team Collaboration
- ✅ Clear contribution process
- ✅ Code review on changes
- ✅ Documentation in one place

---

## 🎓 Best Practices

### 1. Versioning
- Tag all releases (v1.0.0, v1.1.0, etc.)
- Keep CHANGELOG.md updated
- Never force-push to main branch

### 2. Security
- Run security tests before releasing
- Keep dependencies updated
- Review security alerts promptly

### 3. Documentation
- Update README for new features
- Provide migration guides for breaking changes
- Document configuration options

### 4. Testing
- Require all tests pass before merge
- Maintain high test coverage (>80%)
- Add tests for new features

### 5. Communication
- Announce new versions to users
- Document breaking changes clearly
- Provide upgrade guides

---

## 🆘 Troubleshooting

### "Package not found" Error

```bash
# Check URL is correct
pip install -v git+https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0

# For private repos, use SSH or token
pip install git+ssh://git@github.com/YOUR_USERNAME/cloudflare-tunnel-auth.git@v1.0.0
```

### Import Errors

```python
# Make sure you renamed the package
from cloudflare_tunnel_auth import setup_cloudflare_auth  # ✅ Correct

# Not:
from src.cloudflare_auth import setup_cloudflare_auth  # ❌ Old path
```

### Version Conflicts

```bash
# Check installed version
pip show cloudflare-tunnel-auth

# Force reinstall specific version
pip install --force-reinstall cloudflare-tunnel-auth @ git+https://...@v1.0.0
```

### CI/CD Failures

```bash
# Check GitHub Actions logs
# Go to: https://github.com/YOUR_USERNAME/cloudflare-tunnel-auth/actions

# Run tests locally first
pytest tests/ -v
```

---

## 📖 Further Reading

- [README_PACKAGE.md](README_PACKAGE.md) - Package documentation
- [PACKAGE_MIGRATION_GUIDE.md](PACKAGE_MIGRATION_GUIDE.md) - Detailed migration steps
- [CLOUDFLARE_TUNNEL_SECURITY_REVIEW.md](docs/CLOUDFLARE_TUNNEL_SECURITY_REVIEW.md) - Security analysis
- [SECURITY_HARDENING_GUIDE.md](docs/SECURITY_HARDENING_GUIDE.md) - Advanced security
- [pyproject.toml](pyproject.toml) - Package configuration

---

## 🎯 Summary Checklist

### Package Setup
- [ ] Rename `src/cloudflare_auth` to `cloudflare_tunnel_auth`
- [ ] Update imports (relative imports within package)
- [ ] Create package `__init__.py` with exports
- [ ] Test locally: `pip install -e .` and `pytest`

### GitHub Repository
- [ ] Create repository on GitHub
- [ ] Push code: `git push origin main`
- [ ] Tag version: `git tag v1.0.0` and `git push origin v1.0.0`
- [ ] Enable GitHub Actions (automatic)

### Using in Projects
- [ ] Add to `requirements.txt`:
  `cloudflare-tunnel-auth @ git+https://github.com/USER/REPO.git@v1.0.0`
- [ ] Install: `pip install -r requirements.txt`
- [ ] Import: `from cloudflare_tunnel_auth import setup_cloudflare_auth`
- [ ] Configure for each project

### Security & Testing
- [ ] Run security tests: `pytest tests/test_security_vulnerabilities.py`
- [ ] Review security scans in GitHub Actions
- [ ] Keep dependencies updated
- [ ] Monitor for security advisories

**You're ready to use this package across all your projects!** 🎉
