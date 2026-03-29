package authserver

import (
"context"
"errors"
"testing"
"time"

"github.com/SamuelWang/goauth-server/internal/config"
"github.com/SamuelWang/goauth-server/internal/repository"
"github.com/SamuelWang/goauth-server/internal/service/audit"
"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
"github.com/google/uuid"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/mock"
"github.com/stretchr/testify/require"
)

// ── helpers ─────────────────────────────────────────────────────────────

func devServerCfg() config.ServerConfig {
	return config.ServerConfig{Env: "development", Scheme: "http", HostName: "localhost", Port: "8080"}
}

func prodServerCfg() config.ServerConfig {
	return config.ServerConfig{Env: "production", Scheme: "https", HostName: "example.com", Port: "443"}
}

func validAdminCfg() config.BootstrapConfig {
	return config.BootstrapConfig{
		AllowDefaultAdmin:    true,
		DefaultAdminEmail:    "admin@example.com",
		DefaultAdminPassword: "ValidPass1!",
	}
}

func validClientCfg() config.BootstrapConfig {
	return config.BootstrapConfig{
		AllowDefaultClient:        true,
		DefaultClientID:           "default-client",
		DefaultClientSecret:       "supersecretvalue",
		DefaultClientName:         "GoAuth Client",
		DefaultClientConfidential: true,
		DefaultClientRedirectURIs: "https://app.example.com/callback",
	}
}

func sampleUser() repository.User {
	id := uuid.New()
	isAdmin := false
	return repository.User{
		ID:            id,
		Email:         "admin@example.com",
		EmailVerified: true,
		IsActive:      true,
		IsAdmin:       &isAdmin,
		LastLoginAt:   time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func truePtr() *bool { v := true; return &v }

func sampleRepoClient() repository.Client {
	return repository.Client{
		ID:                 uuid.New(),
		Name:               "GoAuth Client",
		ClientSecretHash:   "somehash",
		RedirectUris:       []string{"https://app.example.com/callback"},
		GrantTypes:         []string{"authorization_code"},
		IsActive:           truePtr(),
		CreatedBy:          uuid.Nil,
		IsConfidential:     true,
		AllowRefreshTokens: false,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
}

// newPermissiveMockAuditService returns an audit.Service backed by a MockQuerier
// that accepts any number of CreateAuditLogEntry calls (useful when the test
// is not primarily concerned with audit events).
func newPermissiveMockAuditService(t *testing.T) (*audit.Service, *mocks.MockQuerier) {
	t.Helper()
	q := &mocks.MockQuerier{}
	q.On("CreateAuditLogEntry", mock.Anything, mock.Anything).
		Return(uuid.New(), nil).Maybe()
	return audit.New(q), q
}

// ── BootstrapDefaultAdmin ────────────────────────────────────────────────

// T5.5 case 1: AllowDefaultAdmin=false in production → no-op.
func TestBootstrapDefaultAdmin_ProductionGuard(t *testing.T) {
	cfg := validAdminCfg()
	cfg.AllowDefaultAdmin = false

	q := &mocks.MockQuerier{}
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultAdmin(context.Background(), cfg, prodServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertNotCalled(t, "CountAdminUsers")
	q.AssertNotCalled(t, "CreateUser")
}

// Production + AllowDefaultAdmin=true should proceed past the guard.
func TestBootstrapDefaultAdmin_ProductionWithFlag_Proceeds(t *testing.T) {
	cfg := validAdminCfg()
	cfg.AllowDefaultAdmin = true

	u := sampleUser()
	q := &mocks.MockQuerier{}
	q.On("CountAdminUsers", mock.Anything).Return(int64(0), nil)
	q.On("CreateUser", mock.Anything, mock.MatchedBy(func(p repository.CreateUserParams) bool {
return p.Email == cfg.DefaultAdminEmail
})).Return(u, nil)
	q.On("UpdatePasswordHash", mock.Anything, mock.MatchedBy(func(p repository.UpdatePasswordHashParams) bool {
return p.ID == u.ID && p.PasswordHash != nil
	})).Return(u, nil)
	q.On("SetForcePasswordChange", mock.Anything, repository.SetForcePasswordChangeParams{
ID: u.ID, ForcePasswordChange: true,
}).Return(u, nil)
	q.On("PromoteUserToAdmin", mock.Anything, u.ID).Return(u, nil)
	q.On("CreateAuditLogEntry", mock.Anything, mock.Anything).Return(uuid.New(), nil)

	auditSvc := audit.New(q)

	err := BootstrapDefaultAdmin(context.Background(), cfg, prodServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertCalled(t, "CountAdminUsers", mock.Anything)
}

// T5.5 case 2: Admin already exists → no CreateUser call.
func TestBootstrapDefaultAdmin_AdminAlreadyExists(t *testing.T) {
	cfg := validAdminCfg()

	q := &mocks.MockQuerier{}
	q.On("CountAdminUsers", mock.Anything).Return(int64(1), nil)
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultAdmin(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertNotCalled(t, "CreateUser")
}

// T5.5 case 3: Invalid email → error, no CreateUser call.
func TestBootstrapDefaultAdmin_InvalidEmail(t *testing.T) {
	cfg := validAdminCfg()
	cfg.DefaultAdminEmail = "not-an-email"

	q := &mocks.MockQuerier{}
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultAdmin(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "valid email")
	q.AssertNotCalled(t, "CreateUser")
}

// Missing credentials → no-op without touching the DB.
func TestBootstrapDefaultAdmin_MissingCredentials(t *testing.T) {
	cfg := config.BootstrapConfig{AllowDefaultAdmin: true}

	q := &mocks.MockQuerier{}
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultAdmin(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertNotCalled(t, "CountAdminUsers")
}

// T5.5 case 5: Valid inputs, no existing admin → full success path.
func TestBootstrapDefaultAdmin_Success(t *testing.T) {
	cfg := validAdminCfg()
	u := sampleUser()

	q := &mocks.MockQuerier{}
	q.On("CountAdminUsers", mock.Anything).Return(int64(0), nil)
	q.On("CreateUser", mock.Anything, mock.MatchedBy(func(p repository.CreateUserParams) bool {
return p.Email == cfg.DefaultAdminEmail && p.EmailVerified
	})).Return(u, nil)
	q.On("UpdatePasswordHash", mock.Anything, mock.MatchedBy(func(p repository.UpdatePasswordHashParams) bool {
return p.ID == u.ID && p.PasswordHash != nil && *p.PasswordHash != ""
	})).Return(u, nil)
	q.On("SetForcePasswordChange", mock.Anything, repository.SetForcePasswordChangeParams{
ID: u.ID, ForcePasswordChange: true,
}).Return(u, nil)
	q.On("PromoteUserToAdmin", mock.Anything, u.ID).Return(u, nil)
	q.On("CreateAuditLogEntry", mock.Anything, mock.Anything).Return(uuid.New(), nil)

	auditSvc := audit.New(q)

	err := BootstrapDefaultAdmin(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertExpectations(t)
	q.AssertCalled(t, "PromoteUserToAdmin", mock.Anything, u.ID)
	q.AssertCalled(t, "SetForcePasswordChange", mock.Anything, repository.SetForcePasswordChangeParams{
ID: u.ID, ForcePasswordChange: true,
})
}

// CountAdminUsers DB error → propagated.
func TestBootstrapDefaultAdmin_CountError(t *testing.T) {
	cfg := validAdminCfg()
	dbErr := errors.New("connection refused")

	q := &mocks.MockQuerier{}
	q.On("CountAdminUsers", mock.Anything).Return(int64(0), dbErr)
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultAdmin(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.Error(t, err)
	assert.ErrorIs(t, err, dbErr)
}

// ── BootstrapDefaultClient ───────────────────────────────────────────────

// T5.5 case 6: AllowDefaultClient=false in production → no-op.
func TestBootstrapDefaultClient_ProductionGuard(t *testing.T) {
	cfg := validClientCfg()
	cfg.AllowDefaultClient = false

	q := &mocks.MockQuerier{}
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultClient(context.Background(), cfg, prodServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertNotCalled(t, "CountClients")
	q.AssertNotCalled(t, "CreateClient")
}

// T5.5 case 7: Client already exists → no CreateClient call.
func TestBootstrapDefaultClient_ClientAlreadyExists(t *testing.T) {
	cfg := validClientCfg()

	q := &mocks.MockQuerier{}
	q.On("CountClients", mock.Anything, true).Return(int64(1), nil)
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultClient(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertNotCalled(t, "CreateClient")
}

// T5.5 case 8: Invalid redirect URI → error, no CreateClient call.
func TestBootstrapDefaultClient_InvalidRedirectURI(t *testing.T) {
	cfg := validClientCfg()
	cfg.DefaultClientRedirectURIs = "not-a-valid-uri"

	q := &mocks.MockQuerier{}
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultClient(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid redirect URI")
	q.AssertNotCalled(t, "CreateClient")
}

// Non-HTTPS redirect URI in production → error.
func TestBootstrapDefaultClient_HTTPRedirectInProduction(t *testing.T) {
	cfg := validClientCfg()
	cfg.AllowDefaultClient = true
	cfg.DefaultClientRedirectURIs = "http://app.example.com/callback"

	q := &mocks.MockQuerier{}
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultClient(context.Background(), cfg, prodServerCfg(), q, auditSvc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

// T5.5 case 9: Valid inputs, no existing clients → creates client and writes audit.
func TestBootstrapDefaultClient_Success(t *testing.T) {
	cfg := validClientCfg()
	c := sampleRepoClient()
	secretHash := hashClientSecret(cfg.DefaultClientSecret)
	isActive := true

	q := &mocks.MockQuerier{}
	q.On("CountClients", mock.Anything, true).Return(int64(0), nil)
	q.On("CreateClient", mock.Anything, mock.MatchedBy(func(p repository.CreateClientParams) bool {
return p.Name == cfg.DefaultClientName &&
			p.ClientSecretHash == secretHash &&
			p.IsActive != nil && *p.IsActive == isActive &&
			p.IsConfidential == cfg.DefaultClientConfidential
	})).Return(c, nil)
	q.On("CreateAuditLogEntry", mock.Anything, mock.Anything).Return(uuid.New(), nil)

	auditSvc := audit.New(q)

	err := BootstrapDefaultClient(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertExpectations(t)
}

// Missing credentials → no-op.
func TestBootstrapDefaultClient_MissingCredentials(t *testing.T) {
	cfg := config.BootstrapConfig{AllowDefaultClient: true}

	q := &mocks.MockQuerier{}
	auditSvc, _ := newPermissiveMockAuditService(t)

	err := BootstrapDefaultClient(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertNotCalled(t, "CountClients")
}

// Plain secret must never appear in the stored client record.
func TestBootstrapDefaultClient_SecretIsHashed(t *testing.T) {
	cfg := validClientCfg()
	c := sampleRepoClient()

	q := &mocks.MockQuerier{}
	q.On("CountClients", mock.Anything, true).Return(int64(0), nil)
	q.On("CreateClient", mock.Anything, mock.MatchedBy(func(p repository.CreateClientParams) bool {
// Stored hash must NOT equal the plain-text secret.
return p.ClientSecretHash != cfg.DefaultClientSecret
})).Return(c, nil)
	q.On("CreateAuditLogEntry", mock.Anything, mock.Anything).Return(uuid.New(), nil)

	auditSvc := audit.New(q)

	err := BootstrapDefaultClient(context.Background(), cfg, devServerCfg(), q, auditSvc)
	require.NoError(t, err)
	q.AssertExpectations(t)
}
