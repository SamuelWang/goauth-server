package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	App          AppConfig
	Server       ServerConfig
	Database     DatabaseConfig
	AccessToken  AccessTokenConfig
	Security     SecurityConfig
	Bootstrap    BootstrapConfig
	RefreshToken RefreshTokenConfig
	Lockout      LockoutConfig
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

type AccessTokenConfig struct {
	PrivateKey string
	PublicKey  string
	Expiry     int // in minutes
}

type RefreshTokenConfig struct {
	ExpiryDays      int  // REFRESH_TOKEN_EXPIRY_DAYS (default: 30)
	RotationEnabled bool // REFRESH_TOKEN_ROTATION_ENABLED (default: true)
	MaxLifetimeDays int  // REFRESH_TOKEN_MAX_LIFETIME_DAYS (default: 90)
}

type LockoutConfig struct {
	MaxAttempts     int // LOGIN_MAX_ATTEMPTS (default: 5)
	WindowSeconds   int // LOGIN_ATTEMPT_WINDOW_SECONDS (default: 600)
	DurationSeconds int // LOGIN_LOCKOUT_DURATION_SECONDS (default: 900)
}

type BootstrapConfig struct {
	AllowDefaultAdmin         bool   // ALLOW_DEFAULT_ADMIN (default: false)
	DefaultAdminEmail         string // DEFAULT_ADMIN_EMAIL
	DefaultAdminPassword      string // DEFAULT_ADMIN_PASSWORD
	AllowDefaultClient        bool   // ALLOW_DEFAULT_CLIENT (default: false)
	DefaultClientID           string // DEFAULT_CLIENT_ID
	DefaultClientSecret       string // DEFAULT_CLIENT_SECRET
	DefaultClientRedirectURIs string // DEFAULT_CLIENT_REDIRECT_URIS (comma-separated)
	DefaultClientName         string // DEFAULT_CLIENT_NAME (default: "GoAuth Client")
	DefaultClientConfidential bool   // DEFAULT_CLIENT_CONFIDENTIAL (default: true)
}

type SecurityConfig struct {
	// ProviderEncryptionKey is a hex-encoded 32-byte key used for AES-256-GCM
	// encryption of OAuth provider client secrets at rest.
	ProviderEncryptionKey string

	// SessionSigningKey is a hex-encoded key used for HMAC-SHA256 signing of
	// OAuth session cookies. It must be kept separate from ProviderEncryptionKey
	// to satisfy the key-separation principle.
	SessionSigningKey string

	// CORSAllowedOrigins is a list of origins permitted to make cross-origin
	// requests to the server. Parsed from the CORS_ALLOWED_ORIGINS environment
	// variable (comma-separated, e.g. "https://app.example.com,https://admin.example.com").
	// In production an empty list means no cross-origin requests are allowed.
	// In non-production environments an empty list enables the wildcard (*) fallback.
	CORSAllowedOrigins []string

	// MetricsAllowedCIDRs is the list of CIDRs whose source IPs are permitted
	// to access the /metrics endpoint. Parsed from METRICS_ALLOWED_CIDRS
	// (comma-separated, e.g. "10.0.0.0/8,172.16.0.0/12").
	// When empty, the endpoint is open to all callers.
	MetricsAllowedCIDRs []string
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
		AccessToken: AccessTokenConfig{
			PrivateKey: getEnv("ACCESS_TOKEN_PRIVATE_KEY", ""),
			PublicKey:  getEnv("ACCESS_TOKEN_PUBLIC_KEY", ""),
			Expiry:     getEnvAsInt("ACCESS_TOKEN_EXPIRY_MINUTES", 60),
		},
		Security: SecurityConfig{
			ProviderEncryptionKey: getEnv("PROVIDER_ENCRYPTION_KEY", ""),
			SessionSigningKey:     getEnv("SESSION_SIGNING_KEY", ""),
			CORSAllowedOrigins:    getEnvAsStringSlice("CORS_ALLOWED_ORIGINS"),
			MetricsAllowedCIDRs:   getEnvAsStringSlice("METRICS_ALLOWED_CIDRS"),
		},
		Bootstrap: BootstrapConfig{
			AllowDefaultAdmin:         getEnvAsBool("ALLOW_DEFAULT_ADMIN", false),
			DefaultAdminEmail:         getEnv("DEFAULT_ADMIN_EMAIL", ""),
			DefaultAdminPassword:      getEnv("DEFAULT_ADMIN_PASSWORD", ""),
			AllowDefaultClient:        getEnvAsBool("ALLOW_DEFAULT_CLIENT", false),
			DefaultClientID:           getEnv("DEFAULT_CLIENT_ID", ""),
			DefaultClientSecret:       getEnv("DEFAULT_CLIENT_SECRET", ""),
			DefaultClientRedirectURIs: getEnv("DEFAULT_CLIENT_REDIRECT_URIS", ""),
			DefaultClientName:         getEnv("DEFAULT_CLIENT_NAME", "GoAuth Client"),
			DefaultClientConfidential: getEnvAsBool("DEFAULT_CLIENT_CONFIDENTIAL", true),
		},
	}

	// Parse RefreshTokenConfig — non-numeric values are hard errors.
	var rtErr error
	cfg.RefreshToken.ExpiryDays, rtErr = getEnvAsIntOrError("REFRESH_TOKEN_EXPIRY_DAYS", 30)
	if rtErr != nil {
		return nil, rtErr
	}
	cfg.RefreshToken.RotationEnabled = getEnvAsBool("REFRESH_TOKEN_ROTATION_ENABLED", true)
	cfg.RefreshToken.MaxLifetimeDays, rtErr = getEnvAsIntOrError("REFRESH_TOKEN_MAX_LIFETIME_DAYS", 90)
	if rtErr != nil {
		return nil, rtErr
	}

	// Parse LockoutConfig — non-numeric and zero/negative values are hard errors.
	var lockErr error
	cfg.Lockout.MaxAttempts, lockErr = getEnvAsIntOrError("LOGIN_MAX_ATTEMPTS", 5)
	if lockErr != nil {
		return nil, lockErr
	}
	cfg.Lockout.WindowSeconds, lockErr = getEnvAsIntOrError("LOGIN_ATTEMPT_WINDOW_SECONDS", 600)
	if lockErr != nil {
		return nil, lockErr
	}
	cfg.Lockout.DurationSeconds, lockErr = getEnvAsIntOrError("LOGIN_LOCKOUT_DURATION_SECONDS", 900)
	if lockErr != nil {
		return nil, lockErr
	}
	if cfg.Lockout.MaxAttempts <= 0 {
		return nil, fmt.Errorf("LOGIN_MAX_ATTEMPTS must be positive, got %d", cfg.Lockout.MaxAttempts)
	}
	if cfg.Lockout.WindowSeconds <= 0 {
		return nil, fmt.Errorf("LOGIN_ATTEMPT_WINDOW_SECONDS must be positive, got %d", cfg.Lockout.WindowSeconds)
	}
	if cfg.Lockout.DurationSeconds <= 0 {
		return nil, fmt.Errorf("LOGIN_LOCKOUT_DURATION_SECONDS must be positive, got %d", cfg.Lockout.DurationSeconds)
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

	for _, cidr := range cfg.Security.MetricsAllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("METRICS_ALLOWED_CIDRS contains an invalid CIDR %q: %w", cidr, err)
		}
	}

	// Validate BootstrapConfig fields that carry user-supplied values.
	if cfg.Bootstrap.DefaultAdminEmail != "" {
		if _, err := mail.ParseAddress(cfg.Bootstrap.DefaultAdminEmail); err != nil {
			return nil, fmt.Errorf("DEFAULT_ADMIN_EMAIL is not a valid email address: %w", err)
		}
	}

	// Password policy validation (internal/util/password) is deferred to T7
	// when that package is implemented. A TODO is left here so the call site is
	// already wired correctly once the package exists.
	// TODO(T7): if cfg.Bootstrap.DefaultAdminPassword != "" && cfg.Bootstrap.DefaultAdminEmail != "" {
	//     if err := password.Validate(cfg.Bootstrap.DefaultAdminPassword, cfg.Bootstrap.DefaultAdminEmail); err != nil {
	//         return nil, fmt.Errorf("DEFAULT_ADMIN_PASSWORD does not meet policy: %w", err)
	//     }
	// }

	if cfg.Bootstrap.DefaultClientRedirectURIs != "" {
		for _, raw := range strings.Split(cfg.Bootstrap.DefaultClientRedirectURIs, ",") {
			uri := strings.TrimSpace(raw)
			if uri == "" {
				continue
			}
			if _, err := url.ParseRequestURI(uri); err != nil {
				return nil, fmt.Errorf("DEFAULT_CLIENT_REDIRECT_URIS contains an invalid URI %q: %w", uri, err)
			}
		}
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

// getEnvAsIntOrError reads an integer environment variable. It returns
// defaultValue when the variable is unset or empty, and a descriptive error
// when the value is present but cannot be parsed as an integer.
func getEnvAsIntOrError(key string, defaultValue int) (int, error) {
	str := os.Getenv(key)
	if str == "" {
		return defaultValue, nil
	}
	v, err := strconv.Atoi(strings.TrimSpace(str))
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q", key, str)
	}
	return v, nil
}

func getEnvAsBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true
	case "false":
		return false
	default:
		return defaultValue
	}
}

// getEnvAsStringSlice splits a comma-separated environment variable into a
// slice of trimmed, non-empty strings.  Returns nil when the variable is unset
// or blank.
func getEnvAsStringSlice(key string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
