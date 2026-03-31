package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/util/password"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

// ErrForcePasswordChangeSatisfied is returned when a change-password challenge
// arrives but the force_password_change flag is already false (token reuse).
var ErrForcePasswordChangeSatisfied = errors.New("password change already performed")

// ErrUserNotFound is returned when the user referenced by a challenge token no
// longer exists in the database.
var ErrUserNotFound = errors.New("user not found")

// ChangePasswordResult holds the data needed to issue an access token after a
// successful password change.
type ChangePasswordResult struct {
	UserID string
	Email  string
}

// ChangePassword handles the complete force-password-change flow:
//  1. Fetches the user by ID; returns ErrUserNotFound if missing.
//  2. Returns ErrForcePasswordChangeSatisfied if force_password_change is already false.
//  3. Validates the new password against the complexity policy.
//  4. Hashes the new password with Argon2id and persists it.
//  5. Clears the force_password_change flag.
//  6. Writes two audit log entries (user_password_changed, force_password_change_satisfied).
//
// On success, the caller should generate a new access token using the returned
// ChangePasswordResult values.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, newPassword string) (*ChangePasswordResult, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("fetch user for password change: %w", err)
	}

	if !user.ForcePasswordChange {
		return nil, ErrForcePasswordChangeSatisfied
	}

	if err := password.Validate(newPassword, user.Email); err != nil {
		return nil, err
	}

	hash, err := hashArgon2id(newPassword)
	if err != nil {
		return nil, fmt.Errorf("hashing new password: %w", err)
	}

	if _, err := s.repo.UpdatePasswordHash(ctx, repository.UpdatePasswordHashParams{
		ID:           userID,
		PasswordHash: &hash,
	}); err != nil {
		return nil, fmt.Errorf("updating password hash: %w", err)
	}

	if _, err := s.repo.SetForcePasswordChange(ctx, repository.SetForcePasswordChangeParams{
		ID:                  userID,
		ForcePasswordChange: false,
	}); err != nil {
		return nil, fmt.Errorf("clearing force_password_change: %w", err)
	}

	// Revoke all existing refresh tokens so the old session cannot be resumed.
	reason := "password_change"
	_ = s.repo.RevokeRefreshTokensByUser(ctx, repository.RevokeRefreshTokensByUserParams{
		UserID:       userID,
		RevokeReason: &reason,
	})

	if s.auditSvc != nil {
		uid := userID
		_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
			EventType: audit.EventUserPasswordChanged,
			UserID:    &uid,
		})
		_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
			EventType: audit.EventForcePasswordChangeSatisfied,
			UserID:    &uid,
		})
	}

	return &ChangePasswordResult{
		UserID: user.ID.String(),
		Email:  user.Email,
	}, nil
}

// hashArgon2id derives a storable PHC-formatted Argon2id hash from a plaintext.
// Parameters follow OWASP Password Storage Cheat Sheet recommendations.
func hashArgon2id(plain string) (string, error) {
	const (
		memory      = 64 * 1024
		iterations  = 3
		parallelism = 4
		saltLen     = 16
		keyLen      = 32
	)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(plain), salt, iterations, memory, parallelism, keyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash,
	), nil
}
