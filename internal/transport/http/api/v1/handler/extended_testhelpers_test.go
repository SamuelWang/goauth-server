package handler_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/client"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/service/session"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	v1 "github.com/SamuelWang/goauth-server/internal/transport/http/api/v1"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// newExtendedTestEnv creates a testEnv that additionally configures
// Security.SessionSigningKey (required for challenge token generation),
// LockoutConfig (required for login-lockout tests), and RefreshTokenConfig
// (required for refresh-token rotation tests).
func newExtendedTestEnv(t *testing.T) *testEnv {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalECPrivateKey(privKey)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	// Generate a 32-byte random session signing key (hex-encoded for config).
	signingKeyBytes := make([]byte, 32)
	_, err = rand.Read(signingKeyBytes)
	require.NoError(t, err)
	sessionSigningKey := hex.EncodeToString(signingKeyBytes)

	cfg := &config.Config{
		App:    config.AppConfig{Name: "test-app"},
		Server: config.ServerConfig{Env: "development", Scheme: "http", HostName: "localhost", Port: "8080"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
		Security: config.SecurityConfig{
			SessionSigningKey: sessionSigningKey,
		},
		Lockout: config.LockoutConfig{
			MaxAttempts:     3,
			WindowSeconds:   600,
			DurationSeconds: 900,
		},
		RefreshToken: config.RefreshTokenConfig{
			ExpiryDays:      30,
			RotationEnabled: true,
			MaxLifetimeDays: 90,
		},
	}

	mockQ := &mocks.MockQuerier{}

	authSvc, err := auth.New(mockQ, cfg, nil, nil)
	require.NoError(t, err)

	userSvc := user.New(mockQ)

	encKey := make([]byte, 32)
	_, err = rand.Read(encKey)
	require.NoError(t, err)

	providerSvc, err := provider.New(mockQ, encKey, cfg.Server.Env)
	require.NoError(t, err)

	clientSvc := client.New(mockQ, cfg.Server.Env, nil)
	sessionSvc := session.New(mockQ)

	router := gin.New()
	router.Use(middleware.MaxBodySizeMiddleware())
	router.Use(middleware.SecurityHeadersMiddleware(cfg.Server.Env))
	apiV1 := router.Group("/api/v1")
	apiV1.Use(middleware.ContextMiddleware(cfg))
	v1.RegisterRoutes(apiV1, authSvc, userSvc, providerSvc, clientSvc, sessionSvc, nil)

	return &testEnv{
		mockQ:       mockQ,
		authSvc:     authSvc,
		userSvc:     userSvc,
		providerSvc: providerSvc,
		clientSvc:   clientSvc,
		sessionSvc:  sessionSvc,
		privKey:     privKey,
		router:      router,
	}
}

// buildArgon2Hash derives an Argon2id hash of password using the same parameters
// as the auth service's internal hashArgon2id function. The returned string is
// suitable for use as the PasswordHash field of a mock repository.User.
func buildArgon2Hash(t *testing.T, password string) string {
	t.Helper()

	const (
		memory      = 64 * 1024
		iterations  = 3
		parallelism = 4
		saltLen     = 16
		keyLen      = 32
	)

	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash,
	)
}
