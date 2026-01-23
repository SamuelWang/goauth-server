package models

import (
	"time"

	"github.com/google/uuid"
)

type OAuthProviderData struct{}

type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	FirstName     *string
	LastName      *string
	Locale        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Provider      *string
	ProviderID    *string
	ProviderData  *OAuthProviderData
	LastLoginAt   time.Time
}
