// Package repository — bootstrap helpers.
// This file contains handwritten (non-sqlc) repository methods needed by the
// bootstrap flow. They are intentionally minimal and separated from the
// generated files so that future sqlc regenerations do not overwrite them.
package repository

import (
	"context"

	"github.com/google/uuid"
)

const promoteUserToAdmin = `
UPDATE users
SET is_admin = true,
    updated_at = now()
WHERE id = $1
RETURNING id, email, email_verified, first_name, last_name, is_active, locale,
          provider, provider_id, provider_data, last_login_at, created_at, updated_at,
          is_admin, password_hash, force_password_change, failed_login_attempts,
          last_failed_login_at, locked_until
`

// PromoteUserToAdmin sets is_admin = true for the given user ID. It returns
// the updated User row. This is used exclusively by the bootstrap flow and
// should not be exposed as a general-purpose endpoint.
func (q *Queries) PromoteUserToAdmin(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRow(ctx, promoteUserToAdmin, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.EmailVerified,
		&i.FirstName,
		&i.LastName,
		&i.IsActive,
		&i.Locale,
		&i.Provider,
		&i.ProviderID,
		&i.ProviderData,
		&i.LastLoginAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.IsAdmin,
		&i.PasswordHash,
		&i.ForcePasswordChange,
		&i.FailedLoginAttempts,
		&i.LastFailedLoginAt,
		&i.LockedUntil,
	)
	return i, err
}
