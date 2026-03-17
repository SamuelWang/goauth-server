package util

import (
	"log/slog"
	"os"
	"sync"
)

// SecurityEvent categorises the type of security-relevant event being logged.
type SecurityEvent string

const (
	// EventAuthFailure is emitted when an authentication attempt fails (bad
	// token, expired JWT, revoked token, etc.).
	EventAuthFailure SecurityEvent = "auth_failure"

	// EventRateLimitExceeded is emitted when a request is rejected because it
	// exceeds the configured per-IP or per-user rate limit.
	EventRateLimitExceeded SecurityEvent = "rate_limit_exceeded"

	// EventCSRFViolation is emitted when the CSRF double-submit validation
	// fails on a state-changing request.
	EventCSRFViolation SecurityEvent = "csrf_violation"

	// EventAdminAccessDenied is emitted when an authenticated but non-admin
	// user attempts to reach an admin-only endpoint.
	EventAdminAccessDenied SecurityEvent = "admin_access_denied"

	// EventTokenRevoked is emitted when an access token is voluntarily revoked
	// by the token holder (i.e. on logout).
	EventTokenRevoked SecurityEvent = "token_revoked"

	// EventTokenExchangeFailure is emitted when an authorization-code-for-token
	// exchange fails due to an invalid grant, bad client credentials, or an
	// otherwise invalid request.
	EventTokenExchangeFailure SecurityEvent = "token_exchange_failure"

	// EventOAuthCallbackError is emitted when the OAuth provider returns an
	// error in its callback redirect, or when the callback cannot be processed.
	EventOAuthCallbackError SecurityEvent = "oauth_callback_error"
)

var (
	secLogOnce sync.Once
	secLog     *slog.Logger
)

// getSecurityLogger returns the singleton JSON security logger.  The first
// call initialises the logger; subsequent calls return the cached instance.
func getSecurityLogger() *slog.Logger {
	secLogOnce.Do(func() {
		secLog = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	})
	return secLog
}

// logSecEvent is the internal helper that writes a security event as a
// structured JSON log line at Warn level.
//
// All security events include: time (automatic), msg="security_event",
// event, ip, request_id.  user_id is included only when non-empty.
// callers may append arbitrary key-value pairs via extra.
func logSecEvent(event SecurityEvent, ip, requestID, userID string, extra ...any) {
	attrs := []any{
		"event", string(event),
		"ip", ip,
		"request_id", requestID,
	}
	if userID != "" {
		attrs = append(attrs, "user_id", userID)
	}
	attrs = append(attrs, extra...)
	getSecurityLogger().Warn("security_event", attrs...)
}

// LogAuthFailure logs a failed authentication attempt with the reason the
// request was rejected (e.g. "invalid token", "token revoked",
// "missing token").  userID may be empty when the identity is unknown.
func LogAuthFailure(ip, requestID, userID, reason string) {
	logSecEvent(EventAuthFailure, ip, requestID, userID, "reason", reason)
}

// LogRateLimitExceeded logs a request rejected because it exceeded the
// rate limit.  userID may be empty for unauthenticated callers; path is
// the request path that was blocked.
func LogRateLimitExceeded(ip, requestID, userID, path string) {
	logSecEvent(EventRateLimitExceeded, ip, requestID, userID, "path", path)
}

// LogCSRFViolation logs a state-changing request rejected due to a CSRF token
// mismatch or missing X-CSRF-Token header.
func LogCSRFViolation(ip, requestID, userID, method, path string) {
	logSecEvent(EventCSRFViolation, ip, requestID, userID, "method", method, "path", path)
}

// LogAdminAccessDenied logs an attempt to access an admin-only resource by a
// user who is authenticated but does not have admin privileges.
func LogAdminAccessDenied(ip, requestID, userID, path string) {
	logSecEvent(EventAdminAccessDenied, ip, requestID, userID, "path", path)
}

// LogTokenRevoked logs the voluntary revocation of an access token on logout.
func LogTokenRevoked(ip, requestID, userID string) {
	logSecEvent(EventTokenRevoked, ip, requestID, userID)
}

// LogTokenExchangeFailure logs a failed authorization-code-for-access-token
// exchange.  clientID is the client that submitted the request; reason
// describes the failure (e.g. "invalid_grant", "invalid_client").
func LogTokenExchangeFailure(ip, requestID, clientID, reason string) {
	logSecEvent(EventTokenExchangeFailure, ip, requestID, "" /*userID*/, "client_id", clientID, "reason", reason)
}

// LogOAuthCallbackError logs a failure in the OAuth provider callback, either
// because the provider returned an error or because the callback could not be
// processed (e.g. state mismatch, CSRF detected).
func LogOAuthCallbackError(ip, requestID, clientID, providerName, reason string) {
	logSecEvent(EventOAuthCallbackError, ip, requestID, "", /*userID*/
		"client_id", clientID, "provider", providerName, "reason", reason)
}
