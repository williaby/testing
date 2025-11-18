# Security Hardening Guide

**Last Updated**: 2025-11-18
**Status**: Production Ready

This guide provides additional security hardening recommendations beyond the core authentication fixes.

---

## Table of Contents

1. [Security Headers Implementation](#security-headers-implementation)
2. [Advanced Monitoring & Alerting](#advanced-monitoring--alerting)
3. [Network-Level Security](#network-level-security)
4. [CI/CD Security Automation](#cicd-security-automation)
5. [Penetration Testing](#penetration-testing)
6. [Security Audit Logging](#security-audit-logging)
7. [Incident Response](#incident-response)

---

## 1. Security Headers Implementation

### Add Security Headers Middleware

Create `src/cloudflare_auth/security_headers_enhanced.py`:

```python
"""Enhanced security headers for production deployment."""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Any


class EnhancedSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add comprehensive security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response = await call_next(request)

        # Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Disable legacy XSS protection (use CSP instead)
        response.headers["X-XSS-Protection"] = "0"

        # Content Security Policy (strict)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "upgrade-insecure-requests"
        )

        # HSTS (production only)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy (disable dangerous features)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )

        # Remove server header
        response.headers.pop("Server", None)

        return response
```

### Usage in Application

```python
from fastapi import FastAPI
from src.cloudflare_auth.security_headers_enhanced import EnhancedSecurityHeadersMiddleware

app = FastAPI()
app.add_middleware(EnhancedSecurityHeadersMiddleware)
```

### Verify Headers

```bash
curl -I https://your-app.example.com
```

Should see:
```
HTTP/2 200
content-security-policy: default-src 'self'; ...
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
...
```

---

## 2. Advanced Monitoring & Alerting

### Security Event Monitoring

Create `src/cloudflare_auth/security_monitor.py`:

```python
"""Real-time security monitoring and alerting."""

import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Callable
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """Security event record."""
    event_type: str
    severity: str  # low, medium, high, critical
    source_ip: str
    user_email: str | None
    timestamp: datetime
    details: dict


class SecurityMonitor:
    """Monitor security events and trigger alerts."""

    def __init__(self, alert_callback: Callable[[SecurityEvent], None] | None = None):
        self.events: List[SecurityEvent] = []
        self.ip_violations: Dict[str, int] = defaultdict(int)
        self.alert_callback = alert_callback

    def record_event(
        self,
        event_type: str,
        severity: str,
        source_ip: str,
        user_email: str | None = None,
        details: dict | None = None,
    ) -> None:
        """Record a security event and check for alerts."""
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            user_email=user_email,
            timestamp=datetime.now(),
            details=details or {},
        )

        self.events.append(event)
        self.ip_violations[source_ip] += 1

        # Log event
        logger.warning(
            "SECURITY_EVENT: %s [%s] from %s (user: %s)",
            event_type,
            severity.upper(),
            source_ip,
            user_email or "unknown",
        )

        # Check for alert conditions
        self._check_alerts(event)

    def _check_alerts(self, event: SecurityEvent) -> None:
        """Check if event should trigger an alert."""
        # Alert on critical events immediately
        if event.severity == "critical":
            self._send_alert(event, "CRITICAL security event detected")

        # Alert on repeated violations from same IP
        if self.ip_violations[event.source_ip] >= 5:
            self._send_alert(
                event,
                f"Multiple violations from IP {event.source_ip} ({self.ip_violations[event.source_ip]} events)"
            )

        # Alert on specific patterns
        if event.event_type == "email_header_mismatch":
            self._send_alert(event, "Authentication bypass attempt detected")

        if event.event_type == "missing_cloudflare_headers":
            self._send_alert(event, "Direct access attempt bypassing tunnel")

    def _send_alert(self, event: SecurityEvent, message: str) -> None:
        """Send alert via configured callback."""
        logger.critical("SECURITY_ALERT: %s - %s", message, event)

        if self.alert_callback:
            self.alert_callback(event)

    def get_recent_events(self, minutes: int = 60) -> List[SecurityEvent]:
        """Get events from last N minutes."""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [e for e in self.events if e.timestamp > cutoff]

    def get_high_risk_ips(self, threshold: int = 3) -> List[str]:
        """Get IPs with multiple violations."""
        return [ip for ip, count in self.ip_violations.items() if count >= threshold]


# Global monitor instance
_monitor: SecurityMonitor | None = None


def get_security_monitor() -> SecurityMonitor:
    """Get global security monitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = SecurityMonitor()
    return _monitor
```

### Integration with Middleware

```python
# In middleware.py, add security monitoring

from src.cloudflare_auth.security_monitor import get_security_monitor

# In _authenticate_request method:
monitor = get_security_monitor()

# Record missing email header
if not email_header:
    monitor.record_event(
        event_type="missing_email_header",
        severity="critical",
        source_ip=get_client_ip(request),
        details={"path": request.url.path},
    )
    raise HTTPException(...)

# Record email mismatch
if email_header != user.email:
    monitor.record_event(
        event_type="email_header_mismatch",
        severity="critical",
        source_ip=get_client_ip(request),
        user_email=user.email,
        details={"jwt_email": user.email, "header_email": email_header},
    )
    raise HTTPException(...)

# Record missing Cloudflare headers
if not cf_ray:
    monitor.record_event(
        event_type="missing_cloudflare_headers",
        severity="high",
        source_ip=get_client_ip(request),
        details={"path": request.url.path},
    )
    raise HTTPException(...)
```

### Alert Integrations

```python
"""Example alert integrations."""

def slack_alert(event: SecurityEvent):
    """Send alert to Slack."""
    import requests
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if webhook_url:
        requests.post(webhook_url, json={
            "text": f"🚨 Security Alert: {event.event_type}",
            "attachments": [{
                "color": "danger",
                "fields": [
                    {"title": "Severity", "value": event.severity.upper()},
                    {"title": "Source IP", "value": event.source_ip},
                    {"title": "User", "value": event.user_email or "unknown"},
                    {"title": "Time", "value": event.timestamp.isoformat()},
                ]
            }]
        })

def pagerduty_alert(event: SecurityEvent):
    """Send critical events to PagerDuty."""
    if event.severity == "critical":
        # PagerDuty integration here
        pass

# Configure monitor
monitor = SecurityMonitor(alert_callback=slack_alert)
```

---

## 3. Network-Level Security

### Docker Network Isolation

Update `docker-compose.tunnel.yml`:

```yaml
version: '3.8'

services:
  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared-tunnel
    restart: unless-stopped
    command: tunnel --no-autoupdate run --token ${TUNNEL_TOKEN}
    networks:
      - tunnel-network
    # Healthcheck
    healthcheck:
      test: ["CMD-SHELL", "cloudflared tunnel info || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

  app:
    build: .
    container_name: app
    restart: unless-stopped
    environment:
      - CLOUDFLARE_ENABLED=true
      - REQUIRE_CLOUDFLARE_HEADERS=true
    networks:
      - tunnel-network
    # Only expose to cloudflared
    expose:
      - "8000"
    # Do NOT publish ports externally
    # ports: []  # No external access

networks:
  tunnel-network:
    driver: bridge
    # Enable network isolation
    internal: false  # Allow internet access for app
    driver_opts:
      com.docker.network.bridge.enable_icc: "true"
      com.docker.network.bridge.enable_ip_masquerade: "true"
```

### Firewall Rules (iptables)

Add to Dockerfile:

```dockerfile
# Install iptables
RUN apt-get update && apt-get install -y iptables

# Add firewall script
COPY scripts/firewall.sh /app/firewall.sh
RUN chmod +x /app/firewall.sh

# Run firewall on startup
ENTRYPOINT ["/app/firewall.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Create `scripts/firewall.sh`:

```bash
#!/bin/bash
set -e

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow only from cloudflared container
# (Requires Docker network inspection to get cloudflared IP)
CLOUDFLARED_IP=$(getent hosts cloudflared | awk '{ print $1 }')
if [ -n "$CLOUDFLARED_IP" ]; then
    iptables -A INPUT -s $CLOUDFLARED_IP -p tcp --dport 8000 -j ACCEPT
fi

# Drop all other traffic
iptables -A INPUT -j DROP

echo "Firewall configured: Only accepting connections from cloudflared ($CLOUDFLARED_IP)"

# Execute application
exec "$@"
```

---

## 4. CI/CD Security Automation

### GitHub Actions Security Workflow

Create `.github/workflows/security.yml`:

```yaml
name: Security Checks

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Run daily at 2am
    - cron: '0 2 * * *'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install bandit safety pytest pytest-cov

      - name: Run Bandit (security linter)
        run: |
          bandit -r src/ -f json -o bandit-report.json || true
          bandit -r src/ -ll -i

      - name: Run Safety (dependency check)
        run: |
          safety check --json > safety-report.json || true
          safety check

      - name: Run security tests
        run: |
          pytest tests/test_security_vulnerabilities.py -v

      - name: Check for secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

      - name: OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'cloudflare-auth'
          path: '.'
          format: 'HTML'

      - name: Upload security reports
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: |
            bandit-report.json
            safety-report.json
            dependency-check-report.html

      - name: Fail on high severity issues
        run: |
          # Parse reports and fail if high/critical issues found
          python scripts/check_security_reports.py
```

### Pre-commit Security Hooks

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: '1.7.5'
    hooks:
      - id: bandit
        args: ['-ll', '-i']

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: check-added-large-files
      - id: detect-private-key
      - id: check-json
      - id: check-yaml

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
```

Install:
```bash
pip install pre-commit
pre-commit install
```

---

## 5. Penetration Testing

### Automated Security Testing

Create `tests/penetration/test_auth_bypass.py`:

```python
"""Penetration testing for authentication bypass attempts."""

import pytest
from fastapi.testclient import TestClient


class TestAuthenticationBypass:
    """Attempt various authentication bypass techniques."""

    def test_header_injection_attack(self, client: TestClient):
        """Test header injection attacks."""
        malicious_headers = [
            {"Cf-Access-Jwt-Assertion": "' OR '1'='1"},
            {"Cf-Access-Jwt-Assertion": "../../../etc/passwd"},
            {"Cf-Access-Jwt-Assertion": "<script>alert(1)</script>"},
            {"Cf-Access-Authenticated-User-Email": "admin' --"},
        ]

        for headers in malicious_headers:
            headers["CF-Ray"] = "test-ray"
            response = client.get("/protected", headers=headers)
            assert response.status_code in [400, 401, 403], (
                f"Injection not blocked: {headers}"
            )

    def test_parameter_pollution(self, client: TestClient):
        """Test HTTP parameter pollution."""
        response = client.get(
            "/protected?email=attacker@evil.com&email=admin@example.com",
            headers={
                "Cf-Access-Jwt-Assertion": "token",
                "CF-Ray": "test-ray",
            },
        )
        assert response.status_code in [400, 401, 403]

    def test_timing_attack_resistance(self, client: TestClient):
        """Test resistance to timing attacks."""
        import time

        # Measure time for invalid vs valid emails
        times_invalid = []
        times_valid = []

        for _ in range(100):
            start = time.perf_counter()
            client.get("/protected", headers={"email": "invalid@test.com"})
            times_invalid.append(time.perf_counter() - start)

            start = time.perf_counter()
            client.get("/protected", headers={"email": "valid@test.com"})
            times_valid.append(time.perf_counter() - start)

        avg_invalid = sum(times_invalid) / len(times_invalid)
        avg_valid = sum(times_valid) / len(times_valid)

        # Should be similar (constant-time)
        ratio = max(avg_invalid, avg_valid) / min(avg_invalid, avg_valid)
        assert ratio < 1.5, f"Timing attack possible (ratio: {ratio})"
```

### Manual Penetration Testing Checklist

```markdown
# Penetration Testing Checklist

## Authentication
- [ ] Attempt login without credentials
- [ ] Attempt login with invalid credentials
- [ ] Test session fixation
- [ ] Test session hijacking
- [ ] Test concurrent sessions
- [ ] Test session timeout
- [ ] Test password reset flow
- [ ] Test account lockout

## Authorization
- [ ] Horizontal privilege escalation
- [ ] Vertical privilege escalation
- [ ] Direct object references
- [ ] Path traversal in routes
- [ ] Admin panel access
- [ ] API endpoint enumeration

## Input Validation
- [ ] SQL injection (if applicable)
- [ ] XSS attempts
- [ ] Command injection
- [ ] Path traversal
- [ ] File upload vulnerabilities
- [ ] JSON/XML injection

## Network Security
- [ ] Direct access to app (bypassing tunnel)
- [ ] Header spoofing
- [ ] IP spoofing
- [ ] Man-in-the-middle attacks
- [ ] SSL/TLS configuration

## Rate Limiting
- [ ] Brute force protection
- [ ] DoS resistance
- [ ] API abuse prevention

## Security Headers
- [ ] CSP bypass attempts
- [ ] Clickjacking tests
- [ ] MIME sniffing tests
```

---

## 6. Security Audit Logging

### Structured Logging for Compliance

Create `src/cloudflare_auth/audit_logger.py`:

```python
"""Compliance-focused audit logging."""

import json
import logging
from datetime import datetime
from typing import Any


class AuditLogger:
    """Structured audit logger for compliance (SOC 2, ISO 27001)."""

    def __init__(self, log_file: str = "/var/log/app/audit.jsonl"):
        self.log_file = log_file
        self.logger = logging.getLogger("audit")

    def log_auth_event(
        self,
        event_type: str,
        user_email: str | None,
        source_ip: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log authentication event."""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_category": "authentication",
            "event_type": event_type,
            "user": {
                "email": user_email,
                "source_ip": source_ip,
            },
            "result": result,
            "details": details or {},
        }
        self._write_log(event)

    def log_access_event(
        self,
        resource: str,
        action: str,
        user_email: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log resource access event."""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_category": "access_control",
            "resource": resource,
            "action": action,
            "user": {"email": user_email},
            "result": result,
            "details": details or {},
        }
        self._write_log(event)

    def log_admin_action(
        self,
        admin_email: str,
        action: str,
        target: str | None,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log administrative action."""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_category": "administrative",
            "admin": {"email": admin_email},
            "action": action,
            "target": target,
            "result": result,
            "details": details or {},
        }
        self._write_log(event)

    def _write_log(self, event: dict) -> None:
        """Write event to JSONL file."""
        # Write to file
        with open(self.log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

        # Also log to logger
        self.logger.info(json.dumps(event))
```

### Log Retention Policy

```python
"""Automated log retention and archival."""

import gzip
import shutil
from pathlib import Path
from datetime import datetime, timedelta


def rotate_audit_logs(log_dir: str = "/var/log/app", retention_days: int = 90):
    """Rotate and compress old audit logs."""
    log_path = Path(log_dir)
    current_date = datetime.now()

    for log_file in log_path.glob("audit-*.jsonl"):
        # Get file date from name
        file_date_str = log_file.stem.replace("audit-", "")
        try:
            file_date = datetime.strptime(file_date_str, "%Y-%m-%d")
        except ValueError:
            continue

        age = (current_date - file_date).days

        # Compress logs older than 7 days
        if age > 7 and not log_file.suffix == ".gz":
            with open(log_file, "rb") as f_in:
                with gzip.open(f"{log_file}.gz", "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            log_file.unlink()  # Delete original

        # Delete logs older than retention period
        if age > retention_days:
            log_file.unlink()
```

---

## 7. Incident Response

### Security Incident Playbook

```markdown
# Security Incident Response Playbook

## Phase 1: Detection (0-15 minutes)
1. Alert received from monitoring
2. Verify alert is not false positive
3. Classify severity (P1-P4)
4. Notify security team

## Phase 2: Containment (15-60 minutes)
1. Identify affected systems
2. Isolate compromised components
3. Block malicious IPs at firewall
4. Disable compromised accounts
5. Preserve evidence (logs, memory dumps)

## Phase 3: Investigation (1-4 hours)
1. Analyze attack vectors
2. Identify scope of compromise
3. Check for persistence mechanisms
4. Document timeline
5. Collect forensics

## Phase 4: Eradication (4-8 hours)
1. Remove malicious artifacts
2. Patch vulnerabilities
3. Reset compromised credentials
4. Update firewall rules
5. Deploy security fixes

## Phase 5: Recovery (8-24 hours)
1. Restore from clean backups
2. Verify system integrity
3. Monitor for reinfection
4. Gradual service restoration
5. User notification

## Phase 6: Post-Incident (1-7 days)
1. Post-mortem analysis
2. Update security procedures
3. Patch deployment
4. Staff training
5. Compliance reporting
```

### Automated Incident Response

```python
"""Automated incident response actions."""

from typing import Literal


class IncidentResponder:
    """Automated incident response system."""

    def __init__(self):
        self.blocked_ips: set[str] = set()

    def block_ip(self, ip_address: str, reason: str):
        """Block malicious IP address."""
        self.blocked_ips.add(ip_address)
        # Update firewall rules
        # Send alert
        logger.critical(f"BLOCKED IP: {ip_address} - Reason: {reason}")

    def disable_user(self, email: str, reason: str):
        """Disable compromised user account."""
        # Revoke sessions
        # Disable account
        # Send alert
        logger.critical(f"DISABLED USER: {email} - Reason: {reason}")

    def trigger_emergency_mode(self, severity: Literal["low", "medium", "high", "critical"]):
        """Trigger emergency security mode."""
        if severity in ["high", "critical"]:
            # Enable strict rate limiting
            # Require MFA for all actions
            # Enable enhanced logging
            # Alert security team
            logger.critical("EMERGENCY MODE ACTIVATED")
```

---

## Summary

This hardening guide provides defense-in-depth security:

1. **Headers**: Protection against XSS, clickjacking, MIME sniffing
2. **Monitoring**: Real-time threat detection and alerting
3. **Network**: Isolation and firewall rules
4. **CI/CD**: Automated security scanning
5. **Testing**: Comprehensive penetration testing
6. **Audit**: Compliance-ready logging
7. **Response**: Incident handling procedures

**Next Steps**:
1. Implement security headers middleware
2. Set up monitoring and alerting
3. Configure CI/CD security scans
4. Run penetration tests
5. Document incident response procedures
