// Package main is the entry point for the Goauth Server.
//
// @title           Goauth Server API
// @version         0.3.0
// @description     OAuth 2.0 Authorization Code Grant server with client-scoped provider management.
// @description
// @description     ## OAuth 2.0 Authorization Code Flow
// @description
// @description     ### 1. Discover Enabled Providers
// @description     Fetch the list of OAuth providers enabled for your client:
// @description
// @description         GET /api/v1/clients/{client_id}/auth/providers
// @description
// @description     Returns provider `name` and `display_name` fields only — no credentials or internal URLs.
// @description
// @description     ### 2. Initiate Authorization
// @description     Redirect the user's browser to the login endpoint:
// @description
// @description         GET /web/auth/{client_id}/{provider}/login?redirect_uri={your_redirect_uri}&scope={optional_scope}
// @description
// @description     The server validates the client and provider, stores a signed session cookie containing
// @description     the CSRF state, and redirects the user to the OAuth provider's authorization page.
// @description
// @description     ### 3. Handle Provider Callback
// @description     The OAuth provider redirects the user back to the server's callback endpoint:
// @description
// @description         GET /web/auth/{client_id}/{provider}/callback?code=...&state=...
// @description
// @description     The server validates the CSRF state, exchanges the provider code for user info,
// @description     creates or updates the user record, issues an authorization code, and redirects to:
// @description
// @description         {redirect_uri}?code={authorization_code}
// @description
// @description     ### 4. Exchange Code for Access Token
// @description     Your server exchanges the authorization code for a JWT access token:
// @description
// @description         POST /api/v1/auth/token
// @description         Content-Type: application/json
// @description
// @description         {
// @description           "grant_type":    "authorization_code",
// @description           "code":          "{authorization_code}",
// @description           "client_id":     "{client_uuid}",
// @description           "client_secret": "{client_secret}",
// @description           "redirect_uri":  "{your_redirect_uri}"
// @description         }
// @description
// @description     Authorization codes expire after **5 minutes** and are single-use.
// @description
// @description     ### 5. Use the Access Token
// @description     Include the JWT in the `Authorization` header for authenticated requests:
// @description
// @description         Authorization: Bearer {access_token}
// @description
// @description     Tokens are ECDSA-signed JWTs that expire after **60 minutes** (configurable via
// @description     `ACCESS_TOKEN_EXPIRY_MINUTES`). Revoked tokens are rejected at the middleware layer.
// @description
// @description     ### 6. Logout
// @description     Revoke the access token server-side and clear the session cookie:
// @description
// @description         POST /api/v1/auth/logout
// @description         Authorization: Bearer {access_token}
//
// @contact.name   API Support
//
// @license.name  GPL-3.0 license
//
// @host      localhost:8080
// @BasePath  /
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description ECDSA-signed JWT access token. Format: "Bearer <token>"
package main
