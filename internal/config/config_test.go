package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setEnv sets multiple environment variables and returns a cleanup function
// that restores the previous values.
func setEnv(t *testing.T, pairs map[string]string) {
	t.Helper()
	originals := make(map[string]string, len(pairs))
	for k, v := range pairs {
		originals[k] = os.Getenv(k)
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		for k, orig := range originals {
			if orig == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, orig)
			}
		}
	})
}

// validRequiredEnv returns the minimum environment needed to make Load succeed.
func validRequiredEnv() map[string]string {
	return map[string]string{
		"ACCESS_TOKEN_PRIVATE_KEY": "some-private-key",
		"ACCESS_TOKEN_PUBLIC_KEY":  "some-public-key",
		"PROVIDER_ENCRYPTION_KEY":  "some-enc-key",
		"SESSION_SIGNING_KEY":      "some-sign-key",
	}
}

// ---------------------------------------------------------------------------
// Load – success path
// ---------------------------------------------------------------------------

func TestLoad_Defaults(t *testing.T) {
	// Clear required variables first, then set them.
	setEnv(t, validRequiredEnv())

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "goauth-server", cfg.App.Name)
	assert.Equal(t, "0.3.0", cfg.App.Version)
	assert.Equal(t, "development", cfg.Server.Env)
	assert.Equal(t, "http", cfg.Server.Scheme)
	assert.Equal(t, "localhost", cfg.Server.HostName)
	assert.Equal(t, "8080", cfg.Server.Port)
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, "5432", cfg.Database.Port)
	assert.Equal(t, "postgres", cfg.Database.User)
	assert.Equal(t, "goauth", cfg.Database.DBName)
	assert.Equal(t, "disable", cfg.Database.SSLMode)
	assert.Equal(t, 60, cfg.AccessToken.Expiry)
}

func TestLoad_CustomValues(t *testing.T) {
	setEnv(t, map[string]string{
		"APP_NAME":                    "my-app",
		"VERSION":                     "1.2.3",
		"ENV":                         "production",
		"SCHEME":                      "https",
		"HOST":                        "example.com",
		"PORT":                        "9090",
		"DB_HOST":                     "db.example.com",
		"DB_PORT":                     "5433",
		"DB_USER":                     "myuser",
		"DB_PASSWORD":                 "secret",
		"DB_NAME":                     "mydb",
		"DB_SSLMODE":                  "require",
		"ACCESS_TOKEN_PRIVATE_KEY":    "priv",
		"ACCESS_TOKEN_PUBLIC_KEY":     "pub",
		"ACCESS_TOKEN_EXPIRY_MINUTES": "120",
		"PROVIDER_ENCRYPTION_KEY":     "enckey",
		"SESSION_SIGNING_KEY":         "signkey",
	})

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "my-app", cfg.App.Name)
	assert.Equal(t, "1.2.3", cfg.App.Version)
	assert.Equal(t, "production", cfg.Server.Env)
	assert.Equal(t, "https", cfg.Server.Scheme)
	assert.Equal(t, "example.com", cfg.Server.HostName)
	assert.Equal(t, 120, cfg.AccessToken.Expiry)
}

// ---------------------------------------------------------------------------
// Load – missing required variables
// ---------------------------------------------------------------------------

func TestLoad_MissingPrivateKey(t *testing.T) {
	setEnv(t, map[string]string{
		"ACCESS_TOKEN_PRIVATE_KEY": "",
		"ACCESS_TOKEN_PUBLIC_KEY":  "pub",
		"PROVIDER_ENCRYPTION_KEY":  "enc",
		"SESSION_SIGNING_KEY":      "sign",
	})

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACCESS_TOKEN_PRIVATE_KEY")
}

func TestLoad_MissingPublicKey(t *testing.T) {
	setEnv(t, map[string]string{
		"ACCESS_TOKEN_PRIVATE_KEY": "priv",
		"ACCESS_TOKEN_PUBLIC_KEY":  "",
		"PROVIDER_ENCRYPTION_KEY":  "enc",
		"SESSION_SIGNING_KEY":      "sign",
	})

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACCESS_TOKEN_PUBLIC_KEY")
}

func TestLoad_MissingEncryptionKey(t *testing.T) {
	setEnv(t, map[string]string{
		"ACCESS_TOKEN_PRIVATE_KEY": "priv",
		"ACCESS_TOKEN_PUBLIC_KEY":  "pub",
		"PROVIDER_ENCRYPTION_KEY":  "",
		"SESSION_SIGNING_KEY":      "sign",
	})

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PROVIDER_ENCRYPTION_KEY")
}

func TestLoad_MissingSessionSigningKey(t *testing.T) {
	setEnv(t, map[string]string{
		"ACCESS_TOKEN_PRIVATE_KEY": "priv",
		"ACCESS_TOKEN_PUBLIC_KEY":  "pub",
		"PROVIDER_ENCRYPTION_KEY":  "enc",
		"SESSION_SIGNING_KEY":      "",
	})

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SESSION_SIGNING_KEY")
}

// ---------------------------------------------------------------------------
// ServerConfig helpers
// ---------------------------------------------------------------------------

func TestServerConfig_Host(t *testing.T) {
	cfg := &ServerConfig{HostName: "example.com", Port: "8080"}
	assert.Equal(t, "example.com:8080", cfg.Host())
}

func TestServerConfig_Origin(t *testing.T) {
	cfg := &ServerConfig{Scheme: "https", HostName: "example.com", Port: "443"}
	assert.Equal(t, "https://example.com:443", cfg.Origin())
}

// ---------------------------------------------------------------------------
// DatabaseConfig helpers
// ---------------------------------------------------------------------------

func TestDatabaseConfig_ConnectionString(t *testing.T) {
	cfg := &DatabaseConfig{
		Host:     "db.example.com",
		Port:     "5432",
		User:     "admin",
		Password: "secret",
		DBName:   "mydb",
		SSLMode:  "require",
	}
	cs := cfg.ConnectionString()
	assert.Contains(t, cs, "postgresql://")
	assert.Contains(t, cs, "admin")
	assert.Contains(t, cs, "db.example.com")
	assert.Contains(t, cs, "mydb")
	assert.Contains(t, cs, "require")
}

// ---------------------------------------------------------------------------
// getEnvAsInt
// ---------------------------------------------------------------------------

func TestGetEnvAsInt_DefaultWhenUnset(t *testing.T) {
	os.Unsetenv("TEST_INT_VAR")
	val := getEnvAsInt("TEST_INT_VAR", 42)
	assert.Equal(t, 42, val)
}

func TestGetEnvAsInt_ParsesValidInt(t *testing.T) {
	setEnv(t, map[string]string{"TEST_INT_VAR": "99"})
	val := getEnvAsInt("TEST_INT_VAR", 0)
	assert.Equal(t, 99, val)
}

func TestGetEnvAsInt_DefaultOnInvalidValue(t *testing.T) {
	setEnv(t, map[string]string{"TEST_INT_VAR": "not-a-number"})
	val := getEnvAsInt("TEST_INT_VAR", 7)
	assert.Equal(t, 7, val)
}

// ---------------------------------------------------------------------------
// getEnvAsStringSlice
// ---------------------------------------------------------------------------

func TestGetEnvAsStringSlice_Unset(t *testing.T) {
	os.Unsetenv("TEST_SLICE_VAR")
	result := getEnvAsStringSlice("TEST_SLICE_VAR")
	assert.Nil(t, result)
}

func TestGetEnvAsStringSlice_SingleValue(t *testing.T) {
	setEnv(t, map[string]string{"TEST_SLICE_VAR": "https://example.com"})
	result := getEnvAsStringSlice("TEST_SLICE_VAR")
	assert.Equal(t, []string{"https://example.com"}, result)
}

func TestGetEnvAsStringSlice_MultipleValues(t *testing.T) {
	setEnv(t, map[string]string{"TEST_SLICE_VAR": "https://a.com, https://b.com , https://c.com"})
	result := getEnvAsStringSlice("TEST_SLICE_VAR")
	assert.Equal(t, []string{"https://a.com", "https://b.com", "https://c.com"}, result)
}

func TestGetEnvAsStringSlice_FiltersBlanks(t *testing.T) {
	setEnv(t, map[string]string{"TEST_SLICE_VAR": "a,,b, ,c"})
	result := getEnvAsStringSlice("TEST_SLICE_VAR")
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

// ---------------------------------------------------------------------------
// CORS allowed origins
// ---------------------------------------------------------------------------

func TestLoad_CORSAllowedOrigins(t *testing.T) {
	setEnv(t, map[string]string{
		"ACCESS_TOKEN_PRIVATE_KEY": "priv",
		"ACCESS_TOKEN_PUBLIC_KEY":  "pub",
		"PROVIDER_ENCRYPTION_KEY":  "enc",
		"SESSION_SIGNING_KEY":      "sign",
		"CORS_ALLOWED_ORIGINS":     "https://app.example.com,https://admin.example.com",
	})

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.com", "https://admin.example.com"}, cfg.Security.CORSAllowedOrigins)
}

// ---------------------------------------------------------------------------
// BootstrapConfig defaults
// ---------------------------------------------------------------------------

func TestLoad_BootstrapDefaults(t *testing.T) {
	setEnv(t, validRequiredEnv())

	cfg, err := Load()
	require.NoError(t, err)

	assert.False(t, cfg.Bootstrap.AllowDefaultAdmin)
	assert.Equal(t, "", cfg.Bootstrap.DefaultAdminEmail)
	assert.Equal(t, "", cfg.Bootstrap.DefaultAdminPassword)
	assert.False(t, cfg.Bootstrap.AllowDefaultClient)
	assert.Equal(t, "", cfg.Bootstrap.DefaultClientID)
	assert.Equal(t, "", cfg.Bootstrap.DefaultClientSecret)
	assert.Equal(t, "", cfg.Bootstrap.DefaultClientRedirectURIs)
	assert.Equal(t, "GoAuth Client", cfg.Bootstrap.DefaultClientName)
	assert.True(t, cfg.Bootstrap.DefaultClientConfidential)
}

func TestLoad_BootstrapCustomValues(t *testing.T) {
	env := validRequiredEnv()
	env["ALLOW_DEFAULT_ADMIN"] = "true"
	env["DEFAULT_ADMIN_EMAIL"] = "admin@example.com"
	env["DEFAULT_ADMIN_PASSWORD"] = "AdminPass1!"
	env["ALLOW_DEFAULT_CLIENT"] = "true"
	env["DEFAULT_CLIENT_ID"] = "my-client"
	env["DEFAULT_CLIENT_SECRET"] = "supersecret"
	env["DEFAULT_CLIENT_REDIRECT_URIS"] = "https://app.example.com/callback"
	env["DEFAULT_CLIENT_NAME"] = "My Client"
	env["DEFAULT_CLIENT_CONFIDENTIAL"] = "false"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)

	assert.True(t, cfg.Bootstrap.AllowDefaultAdmin)
	assert.Equal(t, "admin@example.com", cfg.Bootstrap.DefaultAdminEmail)
	assert.Equal(t, "AdminPass1!", cfg.Bootstrap.DefaultAdminPassword)
	assert.True(t, cfg.Bootstrap.AllowDefaultClient)
	assert.Equal(t, "my-client", cfg.Bootstrap.DefaultClientID)
	assert.Equal(t, "supersecret", cfg.Bootstrap.DefaultClientSecret)
	assert.Equal(t, "https://app.example.com/callback", cfg.Bootstrap.DefaultClientRedirectURIs)
	assert.Equal(t, "My Client", cfg.Bootstrap.DefaultClientName)
	assert.False(t, cfg.Bootstrap.DefaultClientConfidential)
}

// ---------------------------------------------------------------------------
// BootstrapConfig – email validation
// ---------------------------------------------------------------------------

func TestLoad_BootstrapInvalidAdminEmail(t *testing.T) {
	env := validRequiredEnv()
	env["DEFAULT_ADMIN_EMAIL"] = "not-a-valid-email"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DEFAULT_ADMIN_EMAIL")
}

func TestLoad_BootstrapValidAdminEmail(t *testing.T) {
	env := validRequiredEnv()
	env["DEFAULT_ADMIN_EMAIL"] = "admin@example.com"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", cfg.Bootstrap.DefaultAdminEmail)
}

func TestLoad_BootstrapEmptyAdminEmail_NoError(t *testing.T) {
	setEnv(t, validRequiredEnv())

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.Bootstrap.DefaultAdminEmail)
}

// ---------------------------------------------------------------------------
// BootstrapConfig – redirect URI validation
// ---------------------------------------------------------------------------

func TestLoad_BootstrapInvalidRedirectURI(t *testing.T) {
	env := validRequiredEnv()
	env["DEFAULT_CLIENT_REDIRECT_URIS"] = "not a valid uri"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DEFAULT_CLIENT_REDIRECT_URIS")
}

func TestLoad_BootstrapValidRedirectURI(t *testing.T) {
	env := validRequiredEnv()
	env["DEFAULT_CLIENT_REDIRECT_URIS"] = "https://app.example.com/callback,https://other.example.com/cb"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "https://app.example.com/callback,https://other.example.com/cb", cfg.Bootstrap.DefaultClientRedirectURIs)
}

func TestLoad_BootstrapRedirectURIWithInvalidEntry(t *testing.T) {
	env := validRequiredEnv()
	env["DEFAULT_CLIENT_REDIRECT_URIS"] = "https://good.example.com/cb, ://bad-uri"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DEFAULT_CLIENT_REDIRECT_URIS")
}

// ---------------------------------------------------------------------------
// RefreshTokenConfig – defaults and parsing
// ---------------------------------------------------------------------------

func TestLoad_RefreshTokenDefaults(t *testing.T) {
	setEnv(t, validRequiredEnv())

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, 30, cfg.RefreshToken.ExpiryDays)
	assert.True(t, cfg.RefreshToken.RotationEnabled)
	assert.Equal(t, 90, cfg.RefreshToken.MaxLifetimeDays)
}

func TestLoad_RefreshTokenCustomValues(t *testing.T) {
	env := validRequiredEnv()
	env["REFRESH_TOKEN_EXPIRY_DAYS"] = "14"
	env["REFRESH_TOKEN_ROTATION_ENABLED"] = "false"
	env["REFRESH_TOKEN_MAX_LIFETIME_DAYS"] = "60"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, 14, cfg.RefreshToken.ExpiryDays)
	assert.False(t, cfg.RefreshToken.RotationEnabled)
	assert.Equal(t, 60, cfg.RefreshToken.MaxLifetimeDays)
}

func TestLoad_RefreshTokenExpiryDays_NonNumeric(t *testing.T) {
	env := validRequiredEnv()
	env["REFRESH_TOKEN_EXPIRY_DAYS"] = "not-a-number"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REFRESH_TOKEN_EXPIRY_DAYS")
}

func TestLoad_RefreshTokenMaxLifetimeDays_NonNumeric(t *testing.T) {
	env := validRequiredEnv()
	env["REFRESH_TOKEN_MAX_LIFETIME_DAYS"] = "abc"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REFRESH_TOKEN_MAX_LIFETIME_DAYS")
}

// ---------------------------------------------------------------------------
// LockoutConfig – defaults and parsing
// ---------------------------------------------------------------------------

func TestLoad_LockoutDefaults(t *testing.T) {
	setEnv(t, validRequiredEnv())

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, 5, cfg.Lockout.MaxAttempts)
	assert.Equal(t, 600, cfg.Lockout.WindowSeconds)
	assert.Equal(t, 900, cfg.Lockout.DurationSeconds)
}

func TestLoad_LockoutCustomValues(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_MAX_ATTEMPTS"] = "10"
	env["LOGIN_ATTEMPT_WINDOW_SECONDS"] = "300"
	env["LOGIN_LOCKOUT_DURATION_SECONDS"] = "1800"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, 10, cfg.Lockout.MaxAttempts)
	assert.Equal(t, 300, cfg.Lockout.WindowSeconds)
	assert.Equal(t, 1800, cfg.Lockout.DurationSeconds)
}

func TestLoad_LockoutMaxAttempts_NonNumeric(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_MAX_ATTEMPTS"] = "abc"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_MAX_ATTEMPTS")
}

func TestLoad_LockoutWindowSeconds_NonNumeric(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_ATTEMPT_WINDOW_SECONDS"] = "not-a-number"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_ATTEMPT_WINDOW_SECONDS")
}

func TestLoad_LockoutDurationSeconds_NonNumeric(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_LOCKOUT_DURATION_SECONDS"] = "xyz"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_LOCKOUT_DURATION_SECONDS")
}

func TestLoad_LockoutMaxAttempts_Zero(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_MAX_ATTEMPTS"] = "0"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_MAX_ATTEMPTS")
}

func TestLoad_LockoutMaxAttempts_Negative(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_MAX_ATTEMPTS"] = "-1"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_MAX_ATTEMPTS")
}

func TestLoad_LockoutWindowSeconds_Zero(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_ATTEMPT_WINDOW_SECONDS"] = "0"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_ATTEMPT_WINDOW_SECONDS")
}

func TestLoad_LockoutWindowSeconds_Negative(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_ATTEMPT_WINDOW_SECONDS"] = "-300"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_ATTEMPT_WINDOW_SECONDS")
}

func TestLoad_LockoutDurationSeconds_Zero(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_LOCKOUT_DURATION_SECONDS"] = "0"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_LOCKOUT_DURATION_SECONDS")
}

func TestLoad_LockoutDurationSeconds_Negative(t *testing.T) {
	env := validRequiredEnv()
	env["LOGIN_LOCKOUT_DURATION_SECONDS"] = "-900"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_LOCKOUT_DURATION_SECONDS")
}
