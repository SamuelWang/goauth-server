package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// User is the service-level representation of a user account.
// Internal OAuth provider fields (Provider, ProviderID, ProviderData) are
// intentionally omitted to avoid leaking OAuth implementation details.
type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	FirstName     *string
	LastName      *string
	IsActive      bool
	IsAdmin       bool
	Locale        string
	LastLoginAt   time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Sentinel errors returned by the user Service.
var (
	ErrUserNotFound = errors.New("user not found")
)

// ListUsersParams carries optional filter and pagination parameters for
// listing users. A nil IsActive filter defaults to active users only.
// A nil IsAdmin filter defaults to non-admin users only; to list both
// admin and non-admin users, two separate calls with explicit filters
// are required (the underlying repository query always applies both filters).
type ListUsersParams struct {
	// IsActive filters by account active status. nil defaults to true (active users).
	IsActive *bool
	// IsAdmin filters by admin status. nil defaults to false (non-admin users).
	IsAdmin *bool
	Limit   int32
	Offset  int32
}

// ListUsersResult is the paginated result for user listings.
type ListUsersResult struct {
	Users []User
	Total int64
}

// Service manages user accounts.
type Service struct {
	repo *repository.Queries
}

// New creates a new user Service.
func New(repo *repository.Queries) *Service {
	return &Service{repo: repo}
}

// ListUsers returns a paginated list of users filtered by active and admin status.
// When params.IsActive is nil, only active users are returned.
// When params.IsAdmin is nil, only non-admin users are returned.
func (s *Service) ListUsers(ctx context.Context, params ListUsersParams) (*ListUsersResult, error) {
	isActive := true
	if params.IsActive != nil {
		isActive = *params.IsActive
	}

	isAdmin := false
	if params.IsAdmin != nil {
		isAdmin = *params.IsAdmin
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}

	users, err := s.repo.ListUsers(ctx, repository.ListUsersParams{
		Column1: isActive,
		Column2: isAdmin,
		Limit:   limit,
		Offset:  params.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}

	total, err := s.repo.CountUsers(ctx, repository.CountUsersParams{
		Column1: isActive,
		Column2: isAdmin,
	})
	if err != nil {
		return nil, fmt.Errorf("counting users: %w", err)
	}

	return &ListUsersResult{
		Users: toUsers(users),
		Total: total,
	}, nil
}

// GetUser returns a user by ID. Returns ErrUserNotFound if no user with
// that ID exists.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	row, err := s.repo.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}
	u := toUser(row)
	return &u, nil
}

// UpdateUserStatus enables or disables a user account by setting is_active.
// Returns ErrUserNotFound if no user with that ID exists.
func (s *Service) UpdateUserStatus(ctx context.Context, id uuid.UUID, isActive bool) (*User, error) {
	row, err := s.repo.UpdateUserActiveStatus(ctx, repository.UpdateUserActiveStatusParams{
		ID:       id,
		IsActive: isActive,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("updating user status: %w", err)
	}
	u := toUser(row)
	return &u, nil
}

// IsAdmin reports whether the user identified by userID has the admin flag set.
// Returns ErrUserNotFound if no user with that ID exists.
func (s *Service) IsAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	row, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrUserNotFound
		}
		return false, fmt.Errorf("getting user for admin check: %w", err)
	}
	if row.IsAdmin == nil {
		return false, nil
	}
	return *row.IsAdmin, nil
}

// toUser maps a repository User record to the service model.
func toUser(r repository.User) User {
	isAdmin := false
	if r.IsAdmin != nil {
		isAdmin = *r.IsAdmin
	}
	return User{
		ID:            r.ID,
		Email:         r.Email,
		EmailVerified: r.EmailVerified,
		FirstName:     r.FirstName,
		LastName:      r.LastName,
		IsActive:      r.IsActive,
		IsAdmin:       isAdmin,
		Locale:        r.Locale,
		LastLoginAt:   r.LastLoginAt,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}

// toUsers converts a slice of repository User records to service models.
func toUsers(rows []repository.User) []User {
	users := make([]User, len(rows))
	for i, row := range rows {
		users[i] = toUser(row)
	}
	return users
}
