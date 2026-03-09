package config

import (
	"fmt"
	"os"
)

type Config struct {
	App         AppConfig
	Server      ServerConfig
	Database    DatabaseConfig
	OAuth       OAuthConfig
	AccessToken AccessTokenConfig
	Security    SecurityConfig
}

type AppConfig struct {
	Name    string
	Version string
}

type ServerConfig struct {
	Env      string
	Scheme   string
	HostName string
	Port     string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type OAuthConfig struct {
	Google GoogleOAuthConfig
}

type GoogleOAuthConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	Scopes       []string
}

type AccessTokenConfig struct {
	PrivateKey string
	PublicKey  string
	Expiry     int // in minutes
}

type SecurityConfig struct {
	// ProviderEncryptionKey is a hex-encoded 32-byte key used for AES-256-GCM
	// encryption of OAuth provider client secrets at rest.
	ProviderEncryptionKey string

	// SessionSigningKey is a hex-encoded key used for HMAC-SHA256 signing of
	// OAuth session cookies. It must be kept separate from ProviderEncryptionKey
	// to satisfy the key-separation principle.
	SessionSigningKey string
}

func Load() (*Config, error) {
	cfg := &Config{
		App: AppConfig{
			Name:    getEnv("APP_NAME", "goauth-server"),
			Version: getEnv("VERSION", "0.0.1"),
		},
		Server: ServerConfig{
			Env:      getEnv("ENV", "development"),
			Scheme:   getEnv("SCHEME", "http"),
			HostName: getEnv("HOST", "localhost"),
			Port:     getEnv("PORT", "8080"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", ""),
			DBName:   getEnv("DB_NAME", "goauth"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		OAuth: OAuthConfig{
			Google: GoogleOAuthConfig{
				Enabled:      getEnv("GOOGLE_ENABLED", "false") == "true",
				ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
				Scopes: []string{
					"openid",
					"https://www.googleapis.com/auth/userinfo.email",
					"https://www.googleapis.com/auth/userinfo.profile",
				},
			},
		},
		AccessToken: AccessTokenConfig{
			PrivateKey: getEnv("ACCESS_TOKEN_PRIVATE_KEY", ""),
			PublicKey:  getEnv("ACCESS_TOKEN_PUBLIC_KEY", ""),
			Expiry:     getEnvAsInt("ACCESS_TOKEN_EXPIRY_MINUTES", 60),
		},
		Security: SecurityConfig{
			ProviderEncryptionKey: getEnv("PROVIDER_ENCRYPTION_KEY", ""),
			SessionSigningKey:     getEnv("SESSION_SIGNING_KEY", ""),
		},
	}

	// Validate required fields
	if cfg.OAuth.Google.Enabled {
		if cfg.OAuth.Google.ClientID == "" {
			return nil, fmt.Errorf("GOOGLE_CLIENT_ID is required")
		}
		if cfg.OAuth.Google.ClientSecret == "" {
			return nil, fmt.Errorf("GOOGLE_CLIENT_SECRET is required")
		}
	}

	if cfg.AccessToken.PrivateKey == "" {
		return nil, fmt.Errorf("ACCESS_TOKEN_PRIVATE_KEY is required")
	}
	if cfg.AccessToken.PublicKey == "" {
		return nil, fmt.Errorf("ACCESS_TOKEN_PUBLIC_KEY is required")
	}
	if cfg.Security.ProviderEncryptionKey == "" {
		return nil, fmt.Errorf("PROVIDER_ENCRYPTION_KEY is required")
	}
	if cfg.Security.SessionSigningKey == "" {
		return nil, fmt.Errorf("SESSION_SIGNING_KEY is required")
	}

	return cfg, nil
}

func (c *ServerConfig) Host() string {
	return c.HostName + ":" + c.Port
}

func (c *ServerConfig) Origin() string {
	return c.Scheme + "://" + c.Host()
}

func (c *DatabaseConfig) ConnectionString() string {
	return fmt.Sprintf(
		"postgresql://%s:%s@%s:%s/%s?sslmode=%s",
		c.User, c.Password, c.Host, c.Port, c.DBName, c.SSLMode,
	)
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	var value int
	if _, err := fmt.Sscanf(valueStr, "%d", &value); err != nil {
		return defaultValue
	}
	return value
}
