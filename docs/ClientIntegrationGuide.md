# Client Integration Guide — Goauth Server v0.2.0

## Document Information

* **Version:** 0.2.0
* **Created:** March 11, 2026
* **Project:** Goauth Server

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Understanding the Client-Scoped Provider Model](#3-understanding-the-client-scoped-provider-model)
4. [Registering Your Client Application](#4-registering-your-client-application)
5. [Configuring OAuth Providers for Your Client](#5-configuring-oauth-providers-for-your-client)
6. [The Authorization Code Flow — Step by Step](#6-the-authorization-code-flow--step-by-step)
   - [Step 1 — Discover Available Providers](#61-step-1--discover-available-providers)
   - [Step 2 — Initiate the Authorization Flow](#62-step-2--initiate-the-authorization-flow)
   - [Step 3 — Handle the Callback](#63-step-3--handle-the-callback)
   - [Step 4 — Exchange the Code for a Token](#64-step-4--exchange-the-code-for-a-token)
   - [Step 5 — Use the Access Token](#65-step-5--use-the-access-token)
   - [Step 6 — Logout](#66-step-6--logout)
7. [Error Handling](#7-error-handling)
8. [Security Considerations](#8-security-considerations)
9. [Complete Code Examples](#9-complete-code-examples)
   - [TypeScript / JavaScript (Browser + Node.js)](#91-typescript--javascript-browser--nodejs)
   - [Python](#92-python)
   - [Go](#93-go)
10. [Multi-Provider Setup Example](#10-multi-provider-setup-example)
11. [Provider Isolation Between Clients](#11-provider-isolation-between-clients)
12. [API Reference Summary](#12-api-reference-summary)

---

## 1. Overview

Goauth Server implements the **OAuth 2.0 Authorization Code Grant** flow (RFC 6749). Your client application redirects users to Goauth, which handles the upstream OAuth exchange with a configured identity provider (e.g. Google, GitHub), and then redirects back to your app with a short-lived **authorization code**. You exchange that code for a **JWT access token** on your backend server.

```
Your App                 Goauth Server                 OAuth Provider
   │                          │                              │
   │─── (1) redirect user ───>│                              │
   │                          │──── (2) redirect to IdP ────>│
   │                          │<──── (3) callback with code ─│
   │<── (4) redirect with ────│                              │
   │        auth code         │                              │
   │                          │                              │
   │──── (5) POST /token ────>│                              │
   │<──── (6) access token ───│                              │
```

**Key properties of issued tokens:**

| Property | Value |
|---|---|
| Format | Signed JWT (ECDSA P-256) |
| Default lifetime | 60 minutes (configurable via `ACCESS_TOKEN_EXPIRY_MINUTES`) |
| Revocable | Yes — immediate effect |
| Transport | `Authorization: Bearer <token>` header or `access_token` cookie |

---

## 2. Prerequisites

Before integrating, you need:

1. A registered **client application** — contact your Goauth administrator to create one.
2. At least one **OAuth provider** configured for your client (e.g. Google, GitHub).
3. Your `client_id` (UUID) and `client_secret` — provided once at registration.
4. A registered `redirect_uri` for your application — must exactly match what you pass in requests.

> **Security note:** Store your `client_secret` in environment variables or a secrets manager. Never embed it in front-end code or source repositories.

---

## 3. Understanding the Client-Scoped Provider Model

Goauth uses a **client-scoped provider** architecture. Each OAuth provider is tied to a specific client application:

```
Client A (UUID: abc-...)
  ├── provider: "google"   (Client A's Google OAuth app)
  └── provider: "github"   (Client A's GitHub OAuth app)

Client B (UUID: def-...)
  ├── provider: "google"   (Client B's own, separate Google OAuth app)
  └── provider: "microsoft"
```

**Important implications:**

- The same provider name (e.g. `"google"`) can be configured differently for each client.
- A provider's API credentials are completely isolated between clients — Client B cannot use Client A's Google configuration.
- When initiating a login flow, you always supply both your `client_id` and the `provider` name.
- Each client only sees its own providers; cross-client access returns HTTP 404.

---

## 4. Registering Your Client Application

Client registration is performed by a Goauth **administrator**. Share the following details with them:

| Field | Description | Example |
|---|---|---|
| `name` | Human-readable application name | `"My SaaS App"` |
| `description` | Optional description | `"Production environment"` |
| `redirect_uris` | Array of allowed redirect URIs (exact match required) | `["https://app.example.com/callback"]` |
| `grant_types` | Must include `"authorization_code"` | `["authorization_code"]` |

The administrator will provide:

| Credential | Description | Storage advice |
|---|---|---|
| `client_id` | UUID — public, included in all requests | Can be stored in front-end config |
| `client_secret` | Opaque random string — **only shown once** | Store in server-side secrets manager |

> **Note:** The `client_secret` is only revealed at creation and during explicit secret regeneration. If lost, the administrator must regenerate it. Any previously issued tokens remain valid until they expire or are revoked.

---

## 5. Configuring OAuth Providers for Your Client

Provider configuration is also an administrator task. For each provider, the administrator configures:

| Field | Description | Example (Google) |
|---|---|---|
| `name` | Internal identifier (lowercase, used in URLs) | `"google"` |
| `display_name` | Human-readable name shown to users | `"Google"` |
| `provider_client_id` | Your OAuth app's client ID at the IdP | `"123...apps.googleusercontent.com"` |
| `provider_client_secret` | Your OAuth app's client secret | `"GOCSPX-..."` |
| `auth_url` | Provider's authorization endpoint | `"https://accounts.google.com/o/oauth2/v2/auth"` |
| `token_url` | Provider's token endpoint | `"https://oauth2.googleapis.com/token"` |
| `user_info_url` | Provider's user-info endpoint | `"https://www.googleapis.com/oauth2/v3/userinfo"` |
| `scopes` | OAuth scopes to request | `["openid", "email", "profile"]` |

> **Security:** Provider credentials (client ID and secret) are AES-256-GCM encrypted at rest and are **never** returned in any API response.

When you ask the administrator to set up a provider, provide them the credentials from your OAuth app registration at the provider (e.g. from the Google Cloud Console or GitHub Developer Settings).

---

## 6. The Authorization Code Flow — Step by Step

### 6.1 Step 1 — Discover Available Providers

Before presenting a login UI, fetch the list of enabled providers for your client. This is a **public endpoint** — no authentication required.

**Request:**

```http
GET /api/v1/clients/{client_id}/auth/providers
```

**Response:**

```json
{
  "providers": [
    { "name": "google",  "display_name": "Google" },
    { "name": "github",  "display_name": "GitHub" }
  ]
}
```

Use `name` when constructing login URLs. Use `display_name` for UI labels.

---

### 6.2 Step 2 — Initiate the Authorization Flow

When the user clicks a "Login with Google" button, redirect their browser to Goauth's login endpoint:

```
GET /web/auth/{client_id}/{provider}/login
```

**Query parameters:**

| Parameter | Required | Description |
|---|---|---|
| `redirect_uri` | **Yes** | Where Goauth redirects after successful authentication. Must exactly match a registered redirect URI for your client. |
| `scope` | No | Space-separated OAuth scopes to request. Defaults to the provider's configured scopes if omitted. |

**Example redirect URL:**

```
https://auth.example.com/web/auth/550e8400-e29b-41d4-a716-446655440000/google/login
  ?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
  &scope=openid%20email%20profile
```

**What Goauth does:**

1. Validates the `client_id` and `provider` combination.
2. Checks that `redirect_uri` is registered for your client.
3. Generates a cryptographically random `state` value for CSRF protection.
4. Stores the state, client context, and redirect URI in a signed, HttpOnly session cookie (`oauth_session`).
5. Redirects the user's browser to the upstream OAuth provider's authorization URL.

> **Rate limit:** 20 requests per minute per IP address.

---

### 6.3 Step 3 — Handle the Callback

After the user authenticates at the OAuth provider, the provider redirects back to Goauth:

```
GET /web/auth/{client_id}/{provider}/callback?code=<provider_code>&state=<state>
```

This URL is **Goauth's internal callback endpoint** — it is called by the OAuth provider, not by your application. You must register it with the upstream provider (e.g. in Google Cloud Console). The URL format is:

```
https://{goauth_host}/web/auth/{client_id}/{provider}/callback
```

**What Goauth does:**

1. Validates the `state` parameter against the session cookie (CSRF protection).
2. Exchanges the provider code for provider tokens.
3. Fetches the user's profile from the provider's user-info endpoint.
4. Creates or updates the user record in Goauth's database.
5. Issues a short-lived (5 minute) **authorization code**.
6. Redirects the user to your `redirect_uri` with the code appended:

```
https://app.example.com/callback?code=<authorization_code>
```

Your application receives the user at your `redirect_uri`. Extract the `code` query parameter — you will exchange it for an access token in the next step.

> **Note:** The `code` must be exchanged within **5 minutes** and can only be used **once**.

---

### 6.4 Step 4 — Exchange the Code for a Token

This step is performed **server-side** — never in browser-side JavaScript, because it requires your `client_secret`.

**Request:**

```http
POST /api/v1/auth/token
Content-Type: application/json

{
  "grant_type":    "authorization_code",
  "code":          "<authorization_code_from_callback>",
  "client_id":     "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "<your_client_secret>",
  "redirect_uri":  "https://app.example.com/callback"
}
```

| Field | Description |
|---|---|
| `grant_type` | Must be `"authorization_code"` |
| `code` | The code received in the callback redirect |
| `client_id` | Your client's UUID |
| `client_secret` | Your client's secret (keep server-side only) |
| `redirect_uri` | Must exactly match the `redirect_uri` used in Step 2 |

**Success response (HTTP 200):**

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type":   "Bearer",
  "expires_in":   3600,
  "scope":        "openid email profile"
}
```

| Field | Description |
|---|---|
| `access_token` | Signed JWT. Include in subsequent API requests. |
| `token_type` | Always `"Bearer"` |
| `expires_in` | Seconds until the token expires (default: 3600) |
| `scope` | OAuth scopes granted (may be absent if no scope was requested) |

> **Rate limit:** 10 requests per minute per IP address.

> **Security:** Issue the token exchange request from your backend server. Never expose `client_secret` to the browser.

---

### 6.5 Step 5 — Use the Access Token

Include the access token in API requests using the `Authorization` header:

```http
GET /api/v1/auth/me
Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
```

Alternatively, Goauth also accepts the token via the `access_token` cookie (for browser-based flows where you set the cookie server-side with `HttpOnly`).

**Get current user profile:**

```http
GET /api/v1/auth/me
Authorization: Bearer <access_token>
```

```json
{
  "user": {
    "id":             "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "email":          "user@example.com",
    "email_verified": true,
    "first_name":     "Jane",
    "last_name":      "Smith",
    "locale":         "en",
    "created_at":     "2026-01-15T10:30:00Z"
  }
}
```

**Token claims (JWT payload):**

The JWT contains the user's ID in the `sub` claim. You can decode it client-side to display user information without an extra API call, but always validate it server-side before trusting it for authorization decisions.

---

### 6.6 Step 6 — Logout

To log a user out, revoke their token. This immediately invalidates it — any subsequent request using the old token will fail with HTTP 401.

**Requires:** Valid Bearer token + CSRF token.

```http
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
Content-Type: application/json
```

**CSRF token:** On first load, Goauth sets a `csrf_token` cookie (non-HttpOnly). Read it from the cookie and include it in the `X-CSRF-Token` header for all state-changing requests (`POST`, `PATCH`, `DELETE`).

**Response (HTTP 200):**

```json
{ "message": "Logged out successfully" }
```

After logout, discard the access token from your application state and clear any cookies you have set. The `access_token` cookie set by Goauth is automatically cleared.

---

## 7. Error Handling

### Token Exchange Errors

The token endpoint returns OAuth 2.0-compliant error responses:

| HTTP Status | `error` | Cause |
|---|---|---|
| 400 | `invalid_request` | Missing or malformed request parameters |
| 400 | `unsupported_grant_type` | `grant_type` is not `"authorization_code"` |
| 400 | `invalid_grant` | Code is expired, already used, revoked, or `redirect_uri`/`client_id` mismatch |
| 401 | `invalid_client` | `client_id` not found, client inactive, or wrong `client_secret` |
| 500 | `server_error` | Internal server error (retry with backoff) |

**Example error response:**

```json
{
  "error":             "invalid_grant",
  "error_description": "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI, or was issued to another client."
}
```

> **Note:** `invalid_grant` uses a generic message regardless of the specific reason. This prevents attackers from determining whether a code existed, was expired, or was issued to a different client.

### Provider Callback Errors

If the user denies access at the OAuth provider, Goauth redirects the user back to your `redirect_uri` and includes the provider's error:

```
GET /web/auth/{client_id}/{provider}/callback?error=access_denied&error_description=...
```

In this case, Goauth returns HTTP 400 to the browser with:

```json
{
  "error":             "access_denied",
  "error_description": "The user denied the authorization request."
}
```

Handle this by redirecting the user to an appropriate page in your application.

### Authentication Errors

Protected endpoints return HTTP 401 when the token is missing, malformed, expired, or revoked:

```json
{ "error": "Unauthorized" }
```

When you receive a 401, redirect the user to begin a new login flow — do not attempt to use the token again.

### CSRF Errors

State-changing requests without a valid CSRF token return HTTP 403. Ensure you always read the `csrf_token` cookie and echo it in the `X-CSRF-Token` header.

---

## 8. Security Considerations

### Protect Your Client Secret

- Store `client_secret` only in server-side environment variables or a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager).
- Never log, commit to source control, or return it to the browser.
- The token exchange (`POST /api/v1/auth/token`) must be performed from your **backend server**.

### Validate the `redirect_uri`

- Register the exact `redirect_uri` values you intend to use with the administrator.
- The `redirect_uri` in the token exchange must match the one used to initiate the flow. Goauth enforces this strictly.
- Use HTTPS for all redirect URIs in production. HTTP is only permitted for loopback addresses (`localhost`, `127.0.0.1`, `::1`).

### State Parameter (CSRF Protection)

Goauth handles CSRF protection internally using a signed `oauth_session` cookie. You do not need to generate or verify the `state` parameter yourself — Goauth validates it during the callback. However, you must ensure:
- The user's browser maintains cookies across the login redirect and the callback.
- Session cookies are not shared across browser tabs initiating simultaneous logins to different providers (Goauth's cookie is `HttpOnly`, scoped to `/`).

### Token Storage

- In browser applications: store tokens in memory (a JavaScript variable or React context). Avoid `localStorage` due to XSS risk.
- If you use an `HttpOnly`, `SameSite=Lax` cookie to store the token, set it from your backend server — never from JavaScript.
- In server-side applications: store tokens in the server session associated with the user.

### CSRF Tokens

For any state-changing request to Goauth (`POST /api/v1/auth/logout`, etc.), read the `csrf_token` cookie and include it in the `X-CSRF-Token` header. The cookie is set on first browser request and is `SameSite=Lax`, `HttpOnly=false` so your JavaScript can read it.

### Token Expiry and Refresh

Access tokens expire in 60 minutes by default. Goauth does not currently issue refresh tokens. When a token expires:
1. Catch the HTTP 401 response.
2. Redirect the user to begin a new login flow.

For long-running sessions, consider initiating a silent re-auth (in a hidden iframe or via a prompt-less redirect) if your provider supports it.

---

## 9. Complete Code Examples

### 9.1 TypeScript / JavaScript (Browser + Node.js)

The following example uses plain `fetch`. Adapt to your framework as needed.

#### Discover providers and build login buttons

```typescript
const GOAUTH_BASE = "https://auth.example.com";
const CLIENT_ID   = "550e8400-e29b-41d4-a716-446655440000";

interface Provider {
  name: string;
  display_name: string;
}

async function fetchProviders(): Promise<Provider[]> {
  const res = await fetch(
    `${GOAUTH_BASE}/api/v1/clients/${CLIENT_ID}/auth/providers`
  );
  if (!res.ok) throw new Error(`Failed to fetch providers: ${res.status}`);
  const data = await res.json();
  return data.providers as Provider[];
}

// Redirect the browser to initiate a login with the chosen provider.
function initiateLogin(providerName: string): void {
  const callbackURI = encodeURIComponent("https://app.example.com/callback");
  window.location.href =
    `${GOAUTH_BASE}/web/auth/${CLIENT_ID}/${providerName}/login` +
    `?redirect_uri=${callbackURI}`;
}

// Call from your page:
fetchProviders().then((providers) => {
  providers.forEach((p) => {
    const btn = document.createElement("button");
    btn.textContent = `Login with ${p.display_name}`;
    btn.onclick = () => initiateLogin(p.name);
    document.body.appendChild(btn);
  });
});
```

#### Server-side token exchange (Node.js / Express)

```typescript
import express, { Request, Response } from "express";

const app = express();
const GOAUTH_BASE     = "https://auth.example.com";
const CLIENT_ID       = process.env.GOAUTH_CLIENT_ID!;
const CLIENT_SECRET   = process.env.GOAUTH_CLIENT_SECRET!;
const REDIRECT_URI    = "https://app.example.com/callback";

app.get("/callback", async (req: Request, res: Response) => {
  const code = req.query.code as string | undefined;

  if (!code) {
    // User denied access or an error occurred.
    const error = req.query.error as string;
    return res.redirect(`/?error=${encodeURIComponent(error ?? "unknown_error")}`);
  }

  try {
    const tokenRes = await fetch(`${GOAUTH_BASE}/api/v1/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type:    "authorization_code",
        code,
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri:  REDIRECT_URI,
      }),
    });

    if (!tokenRes.ok) {
      const err = await tokenRes.json();
      console.error("Token exchange failed:", err);
      return res.redirect(`/?error=${encodeURIComponent(err.error)}`);
    }

    const token = await tokenRes.json();
    // Store token.access_token in a session / HttpOnly cookie.
    res.cookie("access_token", token.access_token, {
      httpOnly: true,
      secure:   true,
      sameSite: "lax",
      maxAge:   token.expires_in * 1000,
    });
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Unexpected error during token exchange:", err);
    res.redirect("/?error=server_error");
  }
});

app.listen(3000);
```

#### Making authenticated requests

```typescript
async function getCurrentUser(accessToken: string) {
  const res = await fetch(`${GOAUTH_BASE}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (res.status === 401) {
    // Token expired or revoked — redirect to login.
    window.location.href = "/login";
    return null;
  }

  if (!res.ok) throw new Error(`Failed to fetch user: ${res.status}`);
  return res.json();
}
```

#### Logout

```typescript
function getCookie(name: string): string | undefined {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${name}=`))
    ?.split("=")[1];
}

async function logout(accessToken: string): Promise<void> {
  const csrfToken = getCookie("csrf_token");

  await fetch(`${GOAUTH_BASE}/api/v1/auth/logout`, {
    method:  "POST",
    headers: {
      Authorization:  `Bearer ${accessToken}`,
      "X-CSRF-Token": csrfToken ?? "",
      "Content-Type": "application/json",
    },
    credentials: "include", // needed to send/receive cookies
  });

  // Clear application state.
  window.location.href = "/";
}
```

---

### 9.2 Python

```python
import os
import requests
from flask import Flask, redirect, request, session, url_for

app = Flask(__name__)
app.secret_key = os.urandom(32)

GOAUTH_BASE   = "https://auth.example.com"
CLIENT_ID     = os.environ["GOAUTH_CLIENT_ID"]
CLIENT_SECRET = os.environ["GOAUTH_CLIENT_SECRET"]
REDIRECT_URI  = "https://app.example.com/callback"


@app.route("/login")
def login():
    """Redirect the user to Goauth to begin the OAuth flow."""
    provider = request.args.get("provider", "google")
    login_url = (
        f"{GOAUTH_BASE}/web/auth/{CLIENT_ID}/{provider}/login"
        f"?redirect_uri={requests.utils.quote(REDIRECT_URI, safe='')}"
    )
    return redirect(login_url)


@app.route("/callback")
def callback():
    """Receive the authorization code and exchange it for a token."""
    error = request.args.get("error")
    if error:
        return redirect(url_for("index", error=error))

    code = request.args.get("code")
    if not code:
        return redirect(url_for("index", error="missing_code"))

    resp = requests.post(
        f"{GOAUTH_BASE}/api/v1/auth/token",
        json={
            "grant_type":    "authorization_code",
            "code":          code,
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri":  REDIRECT_URI,
        },
        timeout=10,
    )

    if not resp.ok:
        err = resp.json()
        return redirect(url_for("index", error=err.get("error", "token_error")))

    token_data = resp.json()
    # Store the access token in the server-side session.
    session["access_token"] = token_data["access_token"]
    session["expires_in"]   = token_data["expires_in"]
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    access_token = session.get("access_token")
    if not access_token:
        return redirect(url_for("login"))

    me_resp = requests.get(
        f"{GOAUTH_BASE}/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )

    if me_resp.status_code == 401:
        session.clear()
        return redirect(url_for("login"))

    user = me_resp.json()["user"]
    return f"Welcome, {user.get('first_name', user['email'])}!"


@app.route("/logout", methods=["POST"])
def logout():
    access_token = session.pop("access_token", None)
    if access_token:
        # The CSRF token is set by Goauth on first request.
        # In a full implementation, pass it from the client via a form field or header.
        requests.post(
            f"{GOAUTH_BASE}/api/v1/auth/logout",
            headers={
                "Authorization":  f"Bearer {access_token}",
                "X-CSRF-Token":   request.cookies.get("csrf_token", ""),
                "Content-Type":   "application/json",
            },
            timeout=10,
        )
    return redirect(url_for("index"))
```

---

### 9.3 Go

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

var (
	goauthBase   = os.Getenv("GOAUTH_BASE")   // e.g. "https://auth.example.com"
	clientID     = os.Getenv("GOAUTH_CLIENT_ID")
	clientSecret = os.Getenv("GOAUTH_CLIENT_SECRET")
	redirectURI  = "https://app.example.com/callback"
)

// TokenResponse mirrors the Goauth token exchange response.
type TokenResponse struct {
	AccessToken string  `json:"access_token"`
	TokenType   string  `json:"token_type"`
	ExpiresIn   int64   `json:"expires_in"`
	Scope       *string `json:"scope,omitempty"`
}

// handleLogin redirects the user to Goauth to begin the OAuth flow.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "google"
	}

	loginURL := fmt.Sprintf(
		"%s/web/auth/%s/%s/login?redirect_uri=%s",
		goauthBase, clientID, provider,
		url.QueryEscape(redirectURI),
	)
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
}

// handleCallback receives the authorization code from Goauth and exchanges it.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		http.Redirect(w, r, "/?error="+url.QueryEscape(errParam), http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code parameter", http.StatusBadRequest)
		return
	}

	token, err := exchangeCode(r.Context(), code)
	if err != nil {
		log.Printf("token exchange failed: %v", err)
		http.Redirect(w, r, "/?error=token_exchange_failed", http.StatusFound)
		return
	}

	// Set the token in an HttpOnly cookie (server-side only).
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token.AccessToken,
		Path:     "/",
		MaxAge:   int(token.ExpiresIn),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func exchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     clientID,
		"client_secret": clientSecret,
		"redirect_uri":  redirectURI,
	})

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		goauthBase+"/api/v1/auth/token",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, respBody)
	}

	var token TokenResponse
	if err := json.Unmarshal(respBody, &token); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	return &token, nil
}

func main() {
	http.HandleFunc("/login",    handleLogin)
	http.HandleFunc("/callback", handleCallback)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## 10. Multi-Provider Setup Example

This section shows how to present multiple login options when your client has Google and GitHub configured.

**Step 1 — Fetch providers on your login page:**

```typescript
const providers = await fetchProviders();
// providers = [
//   { name: "google", display_name: "Google" },
//   { name: "github", display_name: "GitHub" }
// ]
```

**Step 2 — Render login buttons:**

```html
<button onclick="initiateLogin('google')">Login with Google</button>
<button onclick="initiateLogin('github')">Login with GitHub</button>
```

**Step 3 — Single callback endpoint handles all providers:**

Your callback endpoint (`https://app.example.com/callback`) receives the `code` parameter regardless of which provider the user authenticated with. The token exchange follows the same flow for all providers — Goauth handles provider-specific differences internally.

```typescript
// /callback — no provider-specific logic needed
const code = new URLSearchParams(window.location.search).get("code");
const token = await exchangeCodeForToken(code);  // same function for all providers
```

**Step 4 — Consistent user object:**

Goauth normalizes provider-specific user profiles into a consistent user object. Whether the user logged in with Google or GitHub, `GET /api/v1/auth/me` returns the same structure:

```json
{
  "user": {
    "id":             "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "email":          "user@example.com",
    "email_verified": true,
    "first_name":     "Jane",
    "last_name":      "Smith",
    "locale":         "en",
    "created_at":     "2026-01-15T10:30:00Z"
  }
}
```

The same user is matched by email across providers — a user who logs in with Google and then GitHub using the same email address is treated as the same Goauth user.

---

## 11. Provider Isolation Between Clients

Providers configured for Client A are completely isolated from Client B:

- **404, not 403:** Requesting a provider endpoint for a client that doesn't own it returns HTTP 404, not HTTP 403. This prevents information disclosure about which providers exist across clients.
- **No credential sharing:** Even if two clients configure "google", they use separate OAuth app credentials. A compromised Client A secret cannot be used against Client B.
- **Independent enable/disable:** Enabling or disabling a provider for Client A has no effect on Client B's providers.
- **Scoped listings:** `GET /api/v1/clients/{client_id}/auth/providers` only returns providers belonging to that specific `client_id`.

**Illustrative example:**

```
# Client A has Google enabled
GET /api/v1/clients/CLIENT_A_ID/auth/providers
→ 200: { "providers": [{ "name": "google", ... }] }

# Client B has GitHub only
GET /api/v1/clients/CLIENT_B_ID/auth/providers
→ 200: { "providers": [{ "name": "github", ... }] }

# Attempting to use Client B's provider with Client A's ID
GET /web/auth/CLIENT_A_ID/github/login?redirect_uri=...
→ 404 (github not configured for CLIENT_A_ID)
```

---

## 12. API Reference Summary

The following endpoints are relevant to client integrations. For full Swagger documentation, visit `/api/docs/index.html` on your Goauth server.

### Public Endpoints (No Authentication Required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/clients/{client_id}/auth/providers` | List enabled providers for a client |
| `GET` | `/web/auth/{client_id}/{provider}/login` | Initiate OAuth flow (browser redirect) |
| `GET` | `/web/auth/{client_id}/{provider}/callback` | OAuth provider callback (used by IdP, not your app) |
| `POST` | `/api/v1/auth/token` | Exchange authorization code for access token |

### Authenticated Endpoints (Bearer Token Required)

| Method | Path | Description | CSRF Required |
|---|---|---|---|
| `GET` | `/api/v1/auth/me` | Get current user profile | No |
| `POST` | `/api/v1/auth/logout` | Revoke current token and clear session | Yes |

### Request / Response Schemas

**`POST /api/v1/auth/token` — Request body:**

```json
{
  "grant_type":    "authorization_code",
  "code":          "string",
  "client_id":     "uuid",
  "client_secret": "string",
  "redirect_uri":  "string"
}
```

**`POST /api/v1/auth/token` — Success response:**

```json
{
  "access_token": "string",
  "token_type":   "Bearer",
  "expires_in":   3600,
  "scope":        "string (optional)"
}
```

**`GET /api/v1/auth/me` — Success response:**

```json
{
  "user": {
    "id":             "uuid",
    "email":          "string",
    "email_verified": true,
    "first_name":     "string (optional)",
    "last_name":      "string (optional)",
    "locale":         "string",
    "created_at":     "ISO 8601 timestamp"
  }
}
```

### HTTP Headers Reference

| Header | When Required | Description |
|---|---|---|
| `Authorization: Bearer <token>` | Authenticated endpoints | Access token from token exchange |
| `X-CSRF-Token: <token>` | State-changing requests | Value of the `csrf_token` cookie |
| `Content-Type: application/json` | Request bodies | Required for `POST` / `PATCH` with body |

### Rate Limits

| Endpoint | Limit | Window | Key |
|---|---|---|---|
| `POST /api/v1/auth/token` | 10 requests | 1 minute | Per IP |
| `GET /web/auth/*/login` | 20 requests | 1 minute | Per IP |
| Admin endpoints | 30 requests | 1 minute | Per authenticated user |
