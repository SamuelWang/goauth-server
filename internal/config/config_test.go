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
	assert.Equal(t, "0.0.1", cfg.App.Version)
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
