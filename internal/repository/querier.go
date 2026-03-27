package repository

import (
	"context"

	"github.com/google/uuid"
)

// Querier lists every database query method used by the service layer.
// *Queries satisfies this interface, allowing tests to inject mock implementations.
type Querier interface {
	// access_tokens
	CountAccessTokens(ctx context.Context, arg CountAccessTokensParams) (int64, error)
	CreateAccessToken(ctx context.Context, arg CreateAccessTokenParams) (AccessToken, error)
	DeleteExpiredAccessTokens(ctx context.Context) error
	GetAccessToken(ctx context.Context, tokenHash string) (AccessToken, error)
	GetAccessTokenByID(ctx context.Context, id uuid.UUID) (AccessToken, error)
	ListAccessTokens(ctx context.Context, arg ListAccessTokensParams) ([]AccessToken, error)
	RevokeAccessToken(ctx context.Context, id uuid.UUID) error
	RevokeAccessTokensByClient(ctx context.Context, clientID uuid.UUID) error
	RevokeAccessTokensByUser(ctx context.Context, userID uuid.UUID) error

	// authorization_codes
	CountAuthorizationCodes(ctx context.Context, arg CountAuthorizationCodesParams) (int64, error)
	CreateAuthorizationCode(ctx context.Context, arg CreateAuthorizationCodeParams) (AuthorizationCode, error)
	DeleteExpiredAuthorizationCodes(ctx context.Context) error
	GetAuthorizationCode(ctx context.Context, code string) (AuthorizationCode, error)
	GetAuthorizationCodeByID(ctx context.Context, id uuid.UUID) (AuthorizationCode, error)
	ListAuthorizationCodes(ctx context.Context, arg ListAuthorizationCodesParams) ([]AuthorizationCode, error)
	MarkAuthorizationCodeUsed(ctx context.Context, id uuid.UUID) (AuthorizationCode, error)
	RevokeAuthorizationCode(ctx context.Context, id uuid.UUID) error
	RevokeAuthorizationCodeByCode(ctx context.Context, code string) error

	// clients
	CountClients(ctx context.Context, dollar_1 bool) (int64, error)
	CreateClient(ctx context.Context, arg CreateClientParams) (Client, error)
	DeleteClient(ctx context.Context, id uuid.UUID) error
	GetClient(ctx context.Context, id uuid.UUID) (Client, error)
	GetClientByID(ctx context.Context, id uuid.UUID) (Client, error)
	ListClients(ctx context.Context, arg ListClientsParams) ([]Client, error)
	RegenerateClientSecret(ctx context.Context, arg RegenerateClientSecretParams) (Client, error)
	UpdateClient(ctx context.Context, arg UpdateClientParams) (Client, error)

	// oauth_providers
	CreateOAuthProvider(ctx context.Context, arg CreateOAuthProviderParams) (OauthProvider, error)
	DeleteOAuthProvider(ctx context.Context, id uuid.UUID) error
	DisableOAuthProvider(ctx context.Context, id uuid.UUID) error
	GetOAuthProvider(ctx context.Context, id uuid.UUID) (OauthProvider, error)
	GetOAuthProviderByClientAndName(ctx context.Context, arg GetOAuthProviderByClientAndNameParams) (OauthProvider, error)
	ListEnabledOAuthProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]OauthProvider, error)
	ListOAuthProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]OauthProvider, error)
	UpdateOAuthProvider(ctx context.Context, arg UpdateOAuthProviderParams) (OauthProvider, error)

	// users
	CountAdminUsers(ctx context.Context) (int64, error)
	CountUsers(ctx context.Context, arg CountUsersParams) (int64, error)
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByEmailForAuth(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (User, error)
	GetUserByProviderID(ctx context.Context, arg GetUserByProviderIDParams) (User, error)
	GetUsersByAdmin(ctx context.Context, isAdmin *bool) ([]User, error)
	IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) (User, error)
	ListUsers(ctx context.Context, arg ListUsersParams) ([]User, error)
	LockUserAccount(ctx context.Context, arg LockUserAccountParams) (User, error)
	ResetLoginAttempts(ctx context.Context, id uuid.UUID) (User, error)
	SetForcePasswordChange(ctx context.Context, arg SetForcePasswordChangeParams) (User, error)
	UnlockUserAccount(ctx context.Context, id uuid.UUID) (User, error)
	UpdateLastLogin(ctx context.Context, arg UpdateLastLoginParams) (User, error)
	UpdatePasswordHash(ctx context.Context, arg UpdatePasswordHashParams) (User, error)
	UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error)
	UpdateUserActiveStatus(ctx context.Context, arg UpdateUserActiveStatusParams) (User, error)

	// refresh_tokens
	CountRefreshTokensByUser(ctx context.Context, userID uuid.UUID) (int64, error)
	CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (RefreshToken, error)
	DeleteExpiredRefreshTokens(ctx context.Context) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	GetRefreshTokenByID(ctx context.Context, id uuid.UUID) (RefreshToken, error)
	ListRefreshTokensByUser(ctx context.Context, arg ListRefreshTokensByUserParams) ([]RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, id uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, arg RevokeRefreshTokenParams) error
	RevokeRefreshTokenFamily(ctx context.Context, arg RevokeRefreshTokenFamilyParams) error

	// audit_log
	CountAuditLogEntries(ctx context.Context, arg CountAuditLogEntriesParams) (int64, error)
	CreateAuditLogEntry(ctx context.Context, arg CreateAuditLogEntryParams) (uuid.UUID, error)
	ListAuditLogEntries(ctx context.Context, arg ListAuditLogEntriesParams) ([]AuditLog, error)
}
