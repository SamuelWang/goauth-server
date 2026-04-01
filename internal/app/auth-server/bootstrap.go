package authserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/SamuelWang/goauth-server/internal/util/password"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// argon2Params holds the tuning parameters for Argon2id password hashing.
// These values follow current OWASP recommendations (OWASP Password Storage
// Cheat Sheet, 2024).
const (
	argonMemory      = 64 * 1024 // 64 MB
	argonIterations  = 3
	argonParallelism = 4
	argonSaltLen     = 16
	argonKeyLen      = 32
)

// hashPasswordArgon2id derives a storable PHC-formatted Argon2id hash string
// from a plain-text password. The salt is generated from crypto/rand.
func hashPasswordArgon2id(plainPassword string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(plainPassword),
		salt,
		argonIterations,
		argonMemory,
		argonParallelism,
		argonKeyLen,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonIterations,
		argonParallelism,
		b64Salt,
		b64Hash,
	)
	return encoded, nil
}

// validateBootstrapRedirectURI checks that rawURI is a valid URL and enforces
// HTTPS in production (matching the client validation logic).
func validateBootstrapRedirectURI(rawURI, env string) error {
	if strings.TrimSpace(rawURI) == "" {
		return fmt.Errorf("redirect URI must not be empty")
	}
	parsed, err := url.ParseRequestURI(rawURI)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid redirect URI: %q", rawURI)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("redirect URI must use http or https scheme: %q", rawURI)
	}
	if env == "production" && parsed.Scheme == "http" {
		host := parsed.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("redirect URI must use HTTPS in production: %q", rawURI)
		}
	}
	return nil
}

// BootstrapDefaultAdmin creates the first admin account from environment
// configuration. It is idempotent: if any admin already exists in the
// database the function returns nil without making any changes.
//
// In production the caller must explicitly opt-in by setting
// ALLOW_DEFAULT_ADMIN=true; otherwise the function is a no-op.
func BootstrapDefaultAdmin(
	ctx context.Context,
	cfg config.BootstrapConfig,
	serverCfg config.ServerConfig,
	repo repository.Querier,
	auditSvc *audit.Service,
) error {
	// Production guard: skip unless explicitly allowed.
	if serverCfg.Env == "production" && !cfg.AllowDefaultAdmin {
		return nil
	}

	// Skip when required credentials are not configured.
	if cfg.DefaultAdminEmail == "" || cfg.DefaultAdminPassword == "" {
		return nil
	}

	// Validate email address format.
	if _, err := mail.ParseAddress(cfg.DefaultAdminEmail); err != nil {
		return fmt.Errorf("bootstrap: DEFAULT_ADMIN_EMAIL is not a valid email address: %w", err)
	}

	// Validate password complexity before touching the database.
	if err := password.Validate(cfg.DefaultAdminPassword, cfg.DefaultAdminEmail); err != nil {
		return fmt.Errorf("bootstrap: DEFAULT_ADMIN_PASSWORD does not meet policy: %w", err)
	}

	// Idempotency: do nothing if an admin already exists.
	count, err := repo.CountAdminUsers(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap: counting admin users: %w", err)
	}
	if count > 0 {
		return nil
	}

	// Hash password with Argon2id.
	passwordHash, err := hashPasswordArgon2id(cfg.DefaultAdminPassword)
	if err != nil {
		return fmt.Errorf("bootstrap: hashing admin password: %w", err)
	}

	// Create the user record with basic fields; OAuth-specific fields are
	// intentionally left empty for local-auth admin accounts.
	newUser, err := repo.CreateUser(ctx, repository.CreateUserParams{
		Email:         cfg.DefaultAdminEmail,
		EmailVerified: true,
		Locale:        "en-US",
		LastLoginAt:   time.Now(),
	})
	if err != nil {
		return fmt.Errorf("bootstrap: creating default admin user: %w", err)
	}

	// Set password hash.
	if _, err = repo.UpdatePasswordHash(ctx, repository.UpdatePasswordHashParams{
		ID:           newUser.ID,
		PasswordHash: &passwordHash,
	}); err != nil {
		return fmt.Errorf("bootstrap: setting admin password hash: %w", err)
	}

	// Require password rotation on first login.
	if _, err = repo.SetForcePasswordChange(ctx, repository.SetForcePasswordChangeParams{
		ID:                  newUser.ID,
		ForcePasswordChange: true,
	}); err != nil {
		return fmt.Errorf("bootstrap: setting force_password_change: %w", err)
	}

	// Promote the user to admin.
	if _, err = repo.PromoteUserToAdmin(ctx, newUser.ID); err != nil {
		return fmt.Errorf("bootstrap: promoting user to admin: %w", err)
	}

	// Write audit entry — must never include the plaintext password.
	_ = auditSvc.LogEvent(ctx, audit.AuditEntry{
		EventType: audit.EventDefaultAdminCreated,
		UserID:    &newUser.ID,
		Metadata:  map[string]any{"email": cfg.DefaultAdminEmail},
	})

	slog.WarnContext(ctx,
		"Default admin account created — rotate credentials immediately",
		"email", cfg.DefaultAdminEmail,
	)

	return nil
}

// BootstrapDefaultClient creates the first OAuth client from environment
// configuration. It is idempotent: if any active client already exists the
// function returns nil without making any changes.
//
// In production the caller must explicitly opt-in by setting
// ALLOW_DEFAULT_CLIENT=true; otherwise the function is a no-op.
func BootstrapDefaultClient(
	ctx context.Context,
	cfg config.BootstrapConfig,
	serverCfg config.ServerConfig,
	repo repository.Querier,
	auditSvc *audit.Service,
) error {
	// Production guard: skip unless explicitly allowed.
	if serverCfg.Env == "production" && !cfg.AllowDefaultClient {
		return nil
	}

	// Skip when required credentials are not configured.
	if cfg.DefaultClientID == "" || cfg.DefaultClientSecret == "" {
		return nil
	}

	// Parse and validate redirect URIs.
	var redirectURIs []string
	if cfg.DefaultClientRedirectURIs != "" {
		for _, raw := range strings.Split(cfg.DefaultClientRedirectURIs, ",") {
			trimmed := strings.TrimSpace(raw)
			if err := validateBootstrapRedirectURI(trimmed, serverCfg.Env); err != nil {
				return fmt.Errorf("bootstrap: invalid redirect URI %q: %w", trimmed, err)
			}
			redirectURIs = append(redirectURIs, trimmed)
		}
	}

	// Idempotency: do nothing if any active client already exists.
	count, err := repo.CountClients(ctx, true)
	if err != nil {
		return fmt.Errorf("bootstrap: counting clients: %w", err)
	}
	if count > 0 {
		return nil
	}

	// Hash client secret with SHA-256 (never store plain secret).
	secretHash := util.SHA256Hex(cfg.DefaultClientSecret)

	// Use uuid.Nil as the "created_by" for bootstrap-created clients to clearly
	// distinguish them from admin-created clients in the audit trail.
	isActive := true
	newClient, err := repo.CreateClient(ctx, repository.CreateClientParams{
		Name:               cfg.DefaultClientName,
		ClientSecretHash:   secretHash,
		RedirectUris:       redirectURIs,
		GrantTypes:         []string{"authorization_code"},
		IsActive:           &isActive,
		CreatedBy:          uuid.Nil,
		IsConfidential:     cfg.DefaultClientConfidential,
		AllowRefreshTokens: false,
	})
	if err != nil {
		return fmt.Errorf("bootstrap: creating default client: %w", err)
	}

	// Write audit entry — must never include the plaintext secret.
	_ = auditSvc.LogEvent(ctx, audit.AuditEntry{
		EventType: audit.EventDefaultClientCreated,
		ClientID:  &newClient.ID,
		Metadata: map[string]any{
			"client_id": cfg.DefaultClientID,
			"name":      cfg.DefaultClientName,
		},
	})

	slog.WarnContext(ctx,
		"Default client created — rotate credentials immediately",
		"client_id", cfg.DefaultClientID,
		"name", cfg.DefaultClientName,
	)

	return nil
}
