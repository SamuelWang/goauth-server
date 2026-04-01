package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

// Sentinel errors for the direct login flow.
var (
	ErrAccountLocked      = errors.New("account locked")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// VerifyCredentialsResult holds the outcome of a successful credential verification.
type VerifyCredentialsResult struct {
	User                *repository.User
	ForcePasswordChange bool
	// LockedUntil is populated only when ErrAccountLocked is returned.
	LockedUntil *time.Time
}

// VerifyCredentials authenticates a user with email and password, enforcing the
// account lockout policy. sourceIP is recorded in audit log entries.
//
// Returns:
//   - (*VerifyCredentialsResult, nil)    on success
//   - (*VerifyCredentialsResult{LockedUntil: ...}, ErrAccountLocked) when locked
//   - (nil, ErrInvalidCredentials)       for bad credentials or unknown email
func (s *Service) VerifyCredentials(ctx context.Context, email, password, sourceIP string) (*VerifyCredentialsResult, error) {
	// 1. Fetch user — "not found" is indistinguishable from wrong password to callers.
	user, err := s.repo.GetUserByEmailForAuth(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("getting user for auth: %w", err)
	}

	// 2. Active lockout check.
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		return &VerifyCredentialsResult{LockedUntil: user.LockedUntil}, ErrAccountLocked
	}

	// 3. Clear any expired lockout before proceeding.
	if user.LockedUntil != nil {
		if _, err := s.repo.ResetLoginAttempts(ctx, user.ID); err != nil {
			return nil, fmt.Errorf("resetting expired lockout: %w", err)
		}
	}

	// 4. Ensure a password hash is set (local-auth accounts only).
	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}

	// 5. Verify Argon2id password hash.
	match, err := verifyArgon2id(password, *user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verifying password: %w", err)
	}

	if !match {
		// Increment failed-attempt counter; DB sets last_failed_login_at = now().
		updated, err := s.repo.IncrementFailedLoginAttempts(ctx, user.ID)
		if err != nil {
			return nil, fmt.Errorf("incrementing failed login attempts: %w", err)
		}

		attempts := int(updated.FailedLoginAttempts)
		withinWindow := user.LastFailedLoginAt != nil &&
			time.Since(*user.LastFailedLoginAt) <= time.Duration(s.cfg.Lockout.WindowSeconds)*time.Second

		if attempts >= s.cfg.Lockout.MaxAttempts && withinWindow {
			lockedUntil := time.Now().Add(time.Duration(s.cfg.Lockout.DurationSeconds) * time.Second)
			if _, err := s.repo.LockUserAccount(ctx, repository.LockUserAccountParams{
				ID:          user.ID,
				LockedUntil: lockedUntil,
			}); err != nil {
				return nil, fmt.Errorf("locking user account: %w", err)
			}

			if s.auditSvc != nil {
				userID := user.ID
				_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
					EventType: audit.EventAccountLocked,
					UserID:    &userID,
					IPAddress: &sourceIP,
					Metadata:  map[string]any{"email": email},
				})
			}
			return &VerifyCredentialsResult{LockedUntil: &lockedUntil}, ErrAccountLocked
		}

		if s.auditSvc != nil {
			userID := user.ID
			_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
				EventType: audit.EventLoginFailed,
				UserID:    &userID,
				IPAddress: &sourceIP,
				Metadata:  map[string]any{"email": email},
			})
		}
		return nil, ErrInvalidCredentials
	}

	// 6. Successful authentication: clear failed attempts and record login time.
	if _, err := s.repo.ResetLoginAttempts(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("resetting login attempts after success: %w", err)
	}
	updated, err := s.repo.UpdateLastLogin(ctx, repository.UpdateLastLoginParams{
		ID:           user.ID,
		ProviderData: &models.OAuthProviderData{},
		LastLoginAt:  time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("updating last login: %w", err)
	}

	return &VerifyCredentialsResult{
		User:                &updated,
		ForcePasswordChange: updated.ForcePasswordChange,
	}, nil
}

// verifyArgon2id checks a plain password against a PHC-format Argon2id encoded
// hash string of the form:
//
//	$argon2id$v=<version>$m=<memory>,t=<iterations>,p=<parallelism>$<b64-salt>$<b64-hash>
func verifyArgon2id(password, encodedHash string) (bool, error) {
	// Split on "$": expected 6 parts when leading "$" creates an empty part[0].
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("unsupported password hash format")
	}

	// Parse Argon2 parameters from parts[3]: "m=65536,t=3,p=4"
	var memory, iterations uint32
	var parallelism uint8
	for _, kv := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			return false, fmt.Errorf("malformed hash parameter segment: %q", kv)
		}
		v, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			return false, fmt.Errorf("parsing hash parameter %q: %w", kv, err)
		}
		switch pair[0] {
		case "m":
			memory = uint32(v)
		case "t":
			iterations = uint32(v)
		case "p":
			parallelism = uint8(v)
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decoding hash salt: %w", err)
	}
	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decoding stored argon2id hash: %w", err)
	}

	computed := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(storedHash)))
	return subtle.ConstantTimeCompare(computed, storedHash) == 1, nil
}
