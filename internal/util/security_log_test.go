package util

import (
	"testing"
)

// These tests verify that the logging functions complete without panicking.
// Security logs write to stderr; we don't inspect the output but ensure the
// calls are stable (and contribute to coverage).

func TestLogAuthFailure_NoPanic(t *testing.T) {
	LogAuthFailure("192.0.2.1", "req-1", "user-abc", "invalid token")
}

func TestLogAuthFailure_EmptyUserID(t *testing.T) {
	LogAuthFailure("192.0.2.1", "req-2", "", "missing token")
}

func TestLogRateLimitExceeded_NoPanic(t *testing.T) {
	LogRateLimitExceeded("10.0.0.1", "req-3", "", "/api/v1/auth/token")
}

func TestLogRateLimitExceeded_WithUserID(t *testing.T) {
	LogRateLimitExceeded("10.0.0.1", "req-4", "user-xyz", "/api/v1/users")
}

func TestLogCSRFViolation_NoPanic(t *testing.T) {
	LogCSRFViolation("192.0.2.1", "req-5", "user-abc", "POST", "/api/v1/clients")
}

func TestLogAdminAccessDenied_NoPanic(t *testing.T) {
	LogAdminAccessDenied("192.0.2.1", "req-6", "user-abc", "/api/v1/admin")
}

func TestLogTokenRevoked_NoPanic(t *testing.T) {
	LogTokenRevoked("192.0.2.1", "req-7", "user-abc")
}

func TestLogTokenExchangeFailure_NoPanic(t *testing.T) {
	LogTokenExchangeFailure("192.0.2.1", "req-8", "client-id-1", "invalid_grant")
}

func TestLogOAuthCallbackError_NoPanic(t *testing.T) {
	LogOAuthCallbackError("192.0.2.1", "req-9", "client-id-1", "google", "state mismatch")
}

// TestGetSecurityLogger_Singleton verifies the logger is a stable singleton
// (calling it twice returns the same instance).
func TestGetSecurityLogger_Singleton(t *testing.T) {
	l1 := getSecurityLogger()
	l2 := getSecurityLogger()
	if l1 != l2 {
		t.Error("expected getSecurityLogger to return the same instance on repeated calls")
	}
}
