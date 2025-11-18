# Cloudflare Access Setup Guide

This guide walks you through setting up Cloudflare Access for your application and configuring the authentication middleware.

## Prerequisites

- A Cloudflare account with Zero Trust access
- A domain managed by Cloudflare
- An application to protect (can be running locally, on a server, or in Docker)

## Part 1: Cloudflare Access Configuration

### Step 1: Enable Cloudflare Zero Trust

1. Log in to your Cloudflare dashboard
2. Go to **Zero Trust** (or **Cloudflare for Teams**)
3. If this is your first time, follow the setup wizard to create your team

### Step 2: Set Up Identity Provider

1. Go to **Settings** → **Authentication**
2. Click **Add new** under Login methods
3. Choose your identity provider (recommended: Google, Azure AD, or Okta)
4. Follow the provider-specific configuration steps
5. Test the login to ensure it works

### Step 3: Create an Access Application

1. Navigate to **Access** → **Applications**
2. Click **Add an application**
3. Select **Self-hosted**
4. Configure the application:

   **Application Configuration:**
   - **Application name**: Your app name (e.g., "My Docker App")
   - **Session Duration**: Choose based on security needs (e.g., 24 hours)
   - **Application domain**: Your app's URL (e.g., `myapp.example.com`)
   - **Path**: Leave as `/` to protect entire application

   **Identity Providers:**
   - Select the identity provider(s) you configured in Step 2

   **Policies:**
   - Click **Add a policy**
   - **Policy name**: Allow authenticated users
   - **Action**: Allow
   - **Configure rules**: Choose one or more:
     - **Emails**: Specific email addresses
     - **Emails ending in**: Domain-based (e.g., `@example.com`)
     - **Email list**: Import a list of allowed users
   - Click **Save policy**

5. Click **Save application**

### Step 4: Get Your Configuration Values

After creating the application, you need two values:

#### Audience Tag (AUD)
1. Open your application in the Cloudflare dashboard
2. Go to the **Overview** tab
3. Find **Application Audience (AUD) Tag**
4. Copy this value (looks like: `abc123def456ghi789...`)

#### Team Domain
1. In the Cloudflare Zero Trust dashboard
2. Go to **Settings** → **Custom Pages**
3. Your team domain is shown at the top (e.g., `myteam.cloudflareaccess.com`)

**Save these values - you'll need them for your application configuration.**

## Part 2: Cloudflare Tunnel Setup (for Docker on Unraid)

### Step 1: Install Cloudflared Tunnel

For Docker/Unraid, you can use the official Cloudflare tunnel container.

#### Option A: Docker Compose (recommended)

Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared-tunnel
    restart: unless-stopped
    command: tunnel --no-autoupdate run --token ${TUNNEL_TOKEN}
    environment:
      - TUNNEL_TOKEN=${TUNNEL_TOKEN}
```

#### Option B: Docker Run

```bash
docker run -d \
  --name cloudflared-tunnel \
  --restart unless-stopped \
  cloudflare/cloudflared:latest \
  tunnel --no-autoupdate run --token YOUR_TUNNEL_TOKEN
```

### Step 2: Create a Tunnel

1. In Cloudflare Zero Trust dashboard
2. Go to **Networks** → **Tunnels**
3. Click **Create a tunnel**
4. Choose **Cloudflared**
5. Name your tunnel (e.g., "unraid-tunnel")
6. Click **Save tunnel**
7. **Copy the tunnel token** - you'll need this for the Docker container

### Step 3: Configure Tunnel Routes

1. In the tunnel configuration, add a **Public Hostname**:
   - **Subdomain**: Your app subdomain (e.g., `myapp`)
   - **Domain**: Your domain (e.g., `example.com`)
   - **Service**:
     - Type: `HTTP`
     - URL: `http://your-app-container:8000` (or your app's internal address)

2. Click **Save tunnel**

### Step 4: Update DNS

1. Go to your Cloudflare domain's **DNS** settings
2. You should see a CNAME record automatically created for your subdomain
3. Ensure it's pointing to your tunnel UUID

### Step 5: Link Tunnel to Access Application

1. Go back to **Access** → **Applications**
2. Find your application
3. Edit the **Application domain** to match your tunnel hostname (e.g., `myapp.example.com`)
4. Save changes

## Part 3: Application Configuration

### Step 1: Clone or Copy the Auth Module

```bash
# If using in a new project
cp -r src/cloudflare_auth your-project/src/
cp -r src/config your-project/src/
cp requirements.txt your-project/
```

### Step 2: Install Dependencies

```bash
cd your-project
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables

Create a `.env` file in your project root:

```env
# From Step 4 of Part 1
CLOUDFLARE_TEAM_DOMAIN=myteam.cloudflareaccess.com
CLOUDFLARE_AUDIENCE_TAG=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz

# Enable authentication
CLOUDFLARE_ENABLED=true

# Optional: Restrict to specific domains
ALLOWED_EMAIL_DOMAINS=example.com,trusted-partner.com

# Environment
ENVIRONMENT=prod
```

### Step 4: Add to Your FastAPI App

```python
from fastapi import FastAPI
from src.cloudflare_auth import setup_cloudflare_auth

app = FastAPI()

# Setup authentication
setup_cloudflare_auth(
    app,
    excluded_paths=["/health", "/metrics"],
    require_auth=True,
)

# Your routes...
```

### Step 5: Deploy

For Docker:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:

```bash
docker build -t my-app .
docker run -d \
  --name my-app \
  -p 8000:8000 \
  --env-file .env \
  my-app
```

## Part 4: Testing

### Step 1: Test Without Cloudflare (Local)

1. Set `CLOUDFLARE_ENABLED=false` in `.env`
2. Run your app locally
3. Access endpoints to ensure app works

### Step 2: Test With Cloudflare

1. Set `CLOUDFLARE_ENABLED=true`
2. Deploy your app
3. Access via your Cloudflare-protected domain
4. You should be redirected to your identity provider
5. After authentication, you should reach your app
6. Check logs for successful authentication

### Step 3: Verify User Information

Create a test endpoint:

```python
@app.get("/debug/user")
async def debug_user(user: CloudflareUser = Depends(get_current_user)):
    return {
        "email": user.email,
        "user_id": user.user_id,
        "claims": user.claims.dict(),
    }
```

Access this endpoint to verify user data is being extracted correctly.

## Troubleshooting

### "Cannot connect to Cloudflare tunnel"

- Check tunnel is running: `docker logs cloudflared-tunnel`
- Verify tunnel token is correct
- Ensure tunnel status is "Healthy" in Cloudflare dashboard

### "Authentication loop" (keeps redirecting)

- Verify `CLOUDFLARE_AUDIENCE_TAG` matches your application
- Check `CLOUDFLARE_TEAM_DOMAIN` is correct
- Ensure cookies are enabled in browser

### "Missing JWT header"

- Confirm app is accessed via Cloudflare domain (not direct IP)
- Check Cloudflare Access is enabled for the application
- Verify the application domain in Access settings matches your URL

### "Invalid token signature"

- Double-check `CLOUDFLARE_TEAM_DOMAIN` in `.env`
- Ensure system time is synchronized (important for JWT)
- Try refreshing the application in Cloudflare dashboard

### "Email domain not allowed"

- Check `ALLOWED_EMAIL_DOMAINS` setting
- Verify user's email domain matches allowed list
- Remove restriction if you want to allow all authenticated users

## Security Best Practices

1. **Use HTTPS only** - Cloudflare Access requires it
2. **Rotate audience tags** - If compromised, create a new application
3. **Monitor logs** - Watch for failed authentication attempts
4. **Limit email domains** - Use `ALLOWED_EMAIL_DOMAINS` for additional security
5. **Set session duration** - Don't use overly long sessions
6. **Use MFA** - Enable multi-factor authentication in your identity provider
7. **Regular audits** - Review access policies and user access regularly

## Advanced: Multiple Applications on One Server

If you have multiple Docker containers on Unraid:

1. Create one tunnel for all apps
2. Add multiple **Public Hostnames** in the tunnel config:
   - `app1.example.com` → `http://app1-container:8000`
   - `app2.example.com` → `http://app2-container:8000`
3. Create separate Access Applications for each
4. Each app gets its own audience tag
5. Configure each app's `.env` with its specific audience tag

Example tunnel config:

```yaml
Public Hostnames:
  - app1.example.com → http://app1:8000
  - app2.example.com → http://app2:3000
  - app3.example.com → http://app3:5000
```

Then create 3 Access Applications, one for each subdomain.

## Next Steps

- Review the [examples](examples/) directory for complete working examples
- Implement role-based access control using email domains
- Set up monitoring and alerting for authentication failures
- Configure backup authentication methods
- Document your specific setup for team members

## Resources

- [Cloudflare Access Documentation](https://developers.cloudflare.com/cloudflare-one/applications/)
- [Cloudflare Tunnel Documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
