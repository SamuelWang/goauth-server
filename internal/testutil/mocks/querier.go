// Package mocks provides testify/mock-based mock implementations for use
// in service layer unit tests.
package mocks

import (
	"context"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

// MockQuerier is a testify mock that implements repository.Querier.
type MockQuerier struct {
	mock.Mock
}

// Ensure MockQuerier satisfies the Querier interface at compile time.
var _ repository.Querier = (*MockQuerier)(nil)

func (m *MockQuerier) CountAccessTokens(ctx context.Context, arg repository.CountAccessTokensParams) (int64, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQuerier) CreateAccessToken(ctx context.Context, arg repository.CreateAccessTokenParams) (repository.AccessToken, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.AccessToken), args.Error(1)
}

func (m *MockQuerier) DeleteExpiredAccessTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockQuerier) GetAccessToken(ctx context.Context, tokenHash string) (repository.AccessToken, error) {
	args := m.Called(ctx, tokenHash)
	return args.Get(0).(repository.AccessToken), args.Error(1)
}

func (m *MockQuerier) GetAccessTokenByID(ctx context.Context, id uuid.UUID) (repository.AccessToken, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.AccessToken), args.Error(1)
}

func (m *MockQuerier) ListAccessTokens(ctx context.Context, arg repository.ListAccessTokensParams) ([]repository.AccessToken, error) {
	args := m.Called(ctx, arg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.AccessToken), args.Error(1)
}

func (m *MockQuerier) RevokeAccessToken(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockQuerier) RevokeAccessTokensByClient(ctx context.Context, clientID uuid.UUID) error {
	args := m.Called(ctx, clientID)
	return args.Error(0)
}

func (m *MockQuerier) RevokeAccessTokensByUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockQuerier) CountAuthorizationCodes(ctx context.Context, arg repository.CountAuthorizationCodesParams) (int64, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQuerier) CreateAuthorizationCode(ctx context.Context, arg repository.CreateAuthorizationCodeParams) (repository.AuthorizationCode, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.AuthorizationCode), args.Error(1)
}

func (m *MockQuerier) DeleteExpiredAuthorizationCodes(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockQuerier) GetAuthorizationCode(ctx context.Context, code string) (repository.AuthorizationCode, error) {
	args := m.Called(ctx, code)
	return args.Get(0).(repository.AuthorizationCode), args.Error(1)
}

func (m *MockQuerier) GetAuthorizationCodeByID(ctx context.Context, id uuid.UUID) (repository.AuthorizationCode, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.AuthorizationCode), args.Error(1)
}

func (m *MockQuerier) ListAuthorizationCodes(ctx context.Context, arg repository.ListAuthorizationCodesParams) ([]repository.AuthorizationCode, error) {
	args := m.Called(ctx, arg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.AuthorizationCode), args.Error(1)
}

func (m *MockQuerier) MarkAuthorizationCodeUsed(ctx context.Context, id uuid.UUID) (repository.AuthorizationCode, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.AuthorizationCode), args.Error(1)
}

func (m *MockQuerier) RevokeAuthorizationCode(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockQuerier) RevokeAuthorizationCodeByCode(ctx context.Context, code string) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *MockQuerier) CountClients(ctx context.Context, dollar_1 bool) (int64, error) {
	args := m.Called(ctx, dollar_1)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQuerier) CreateClient(ctx context.Context, arg repository.CreateClientParams) (repository.Client, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.Client), args.Error(1)
}

func (m *MockQuerier) DeleteClient(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockQuerier) GetClient(ctx context.Context, id uuid.UUID) (repository.Client, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.Client), args.Error(1)
}

func (m *MockQuerier) GetClientByID(ctx context.Context, id uuid.UUID) (repository.Client, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.Client), args.Error(1)
}

func (m *MockQuerier) ListClients(ctx context.Context, arg repository.ListClientsParams) ([]repository.Client, error) {
	args := m.Called(ctx, arg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.Client), args.Error(1)
}

func (m *MockQuerier) RegenerateClientSecret(ctx context.Context, arg repository.RegenerateClientSecretParams) (repository.Client, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.Client), args.Error(1)
}

func (m *MockQuerier) UpdateClient(ctx context.Context, arg repository.UpdateClientParams) (repository.Client, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.Client), args.Error(1)
}

func (m *MockQuerier) CreateOAuthProvider(ctx context.Context, arg repository.CreateOAuthProviderParams) (repository.OauthProvider, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.OauthProvider), args.Error(1)
}

func (m *MockQuerier) DeleteOAuthProvider(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockQuerier) DisableOAuthProvider(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockQuerier) GetOAuthProvider(ctx context.Context, id uuid.UUID) (repository.OauthProvider, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.OauthProvider), args.Error(1)
}

func (m *MockQuerier) GetOAuthProviderByClientAndName(ctx context.Context, arg repository.GetOAuthProviderByClientAndNameParams) (repository.OauthProvider, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.OauthProvider), args.Error(1)
}

func (m *MockQuerier) ListEnabledOAuthProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]repository.OauthProvider, error) {
	args := m.Called(ctx, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.OauthProvider), args.Error(1)
}

func (m *MockQuerier) ListOAuthProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]repository.OauthProvider, error) {
	args := m.Called(ctx, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.OauthProvider), args.Error(1)
}

func (m *MockQuerier) UpdateOAuthProvider(ctx context.Context, arg repository.UpdateOAuthProviderParams) (repository.OauthProvider, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.OauthProvider), args.Error(1)
}

func (m *MockQuerier) CountUsers(ctx context.Context, arg repository.CountUsersParams) (int64, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQuerier) CreateUser(ctx context.Context, arg repository.CreateUserParams) (repository.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) GetUserByEmail(ctx context.Context, email string) (repository.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) GetUserByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) GetUserByProviderID(ctx context.Context, arg repository.GetUserByProviderIDParams) (repository.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) GetUsersByAdmin(ctx context.Context, isAdmin *bool) ([]repository.User, error) {
	args := m.Called(ctx, isAdmin)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.User), args.Error(1)
}

func (m *MockQuerier) ListUsers(ctx context.Context, arg repository.ListUsersParams) ([]repository.User, error) {
	args := m.Called(ctx, arg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.User), args.Error(1)
}

func (m *MockQuerier) UpdateLastLogin(ctx context.Context, arg repository.UpdateLastLoginParams) (repository.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) UpdateUser(ctx context.Context, arg repository.UpdateUserParams) (repository.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) UpdateUserActiveStatus(ctx context.Context, arg repository.UpdateUserActiveStatusParams) (repository.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.User), args.Error(1)
}

// New user methods added in v0.3.0 (sub-tasks 1.5)

func (m *MockQuerier) CountAdminUsers(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQuerier) PromoteUserToAdmin(ctx context.Context, id uuid.UUID) (repository.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) GetUserByEmailForAuth(ctx context.Context, email string) (repository.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) (repository.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) LockUserAccount(ctx context.Context, arg repository.LockUserAccountParams) (repository.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) ResetLoginAttempts(ctx context.Context, id uuid.UUID) (repository.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) SetForcePasswordChange(ctx context.Context, arg repository.SetForcePasswordChangeParams) (repository.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) UnlockUserAccount(ctx context.Context, id uuid.UUID) (repository.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.User), args.Error(1)
}

func (m *MockQuerier) UpdatePasswordHash(ctx context.Context, arg repository.UpdatePasswordHashParams) (repository.User, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.User), args.Error(1)
}

// Refresh token methods added in v0.3.0 (sub-task 1.7)

func (m *MockQuerier) CountRefreshTokensByUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQuerier) CreateRefreshToken(ctx context.Context, arg repository.CreateRefreshTokenParams) (repository.RefreshToken, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(repository.RefreshToken), args.Error(1)
}

func (m *MockQuerier) DeleteExpiredRefreshTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockQuerier) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (repository.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	return args.Get(0).(repository.RefreshToken), args.Error(1)
}

func (m *MockQuerier) GetRefreshTokenByID(ctx context.Context, id uuid.UUID) (repository.RefreshToken, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(repository.RefreshToken), args.Error(1)
}

func (m *MockQuerier) ListRefreshTokensByUser(ctx context.Context, arg repository.ListRefreshTokensByUserParams) ([]repository.RefreshToken, error) {
	args := m.Called(ctx, arg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.RefreshToken), args.Error(1)
}

func (m *MockQuerier) MarkRefreshTokenUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockQuerier) RevokeRefreshToken(ctx context.Context, arg repository.RevokeRefreshTokenParams) error {
	args := m.Called(ctx, arg)
	return args.Error(0)
}

func (m *MockQuerier) RevokeRefreshTokenFamily(ctx context.Context, arg repository.RevokeRefreshTokenFamilyParams) error {
	args := m.Called(ctx, arg)
	return args.Error(0)
}

// Audit log methods added in v0.3.0 (sub-task 1.8)

func (m *MockQuerier) CountAuditLogEntries(ctx context.Context, arg repository.CountAuditLogEntriesParams) (int64, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQuerier) CreateAuditLogEntry(ctx context.Context, arg repository.CreateAuditLogEntryParams) (uuid.UUID, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockQuerier) ListAuditLogEntries(ctx context.Context, arg repository.ListAuditLogEntriesParams) ([]repository.AuditLog, error) {
	args := m.Called(ctx, arg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repository.AuditLog), args.Error(1)
}
