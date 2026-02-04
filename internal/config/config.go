package config

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v9"
)

// Config holds all configuration for the application.
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Tailscale TailscaleConfig
	Sync      SyncConfig
	OIDC      OIDCConfig
}

// OIDCConfig holds OIDC authentication configuration.
type OIDCConfig struct {
	Enabled         bool          `env:"OIDC_ENABLED" envDefault:"false"`
	IssuerURL       string        `env:"OIDC_ISSUER_URL"`
	ClientID        string        `env:"OIDC_CLIENT_ID"`
	ClientSecret    string        `env:"OIDC_CLIENT_SECRET"`
	RedirectURL     string        `env:"OIDC_REDIRECT_URL"`
	Scopes          string        `env:"OIDC_SCOPES" envDefault:"openid,email,profile"`
	SessionSecret   string        `env:"OIDC_SESSION_SECRET"`
	SessionDuration time.Duration `env:"OIDC_SESSION_DURATION" envDefault:"24h"`
	AllowedDomains  string        `env:"OIDC_ALLOWED_DOMAINS"`
	LogoutURL       string        `env:"OIDC_LOGOUT_URL"`
}

// GetScopes returns the OIDC scopes as a slice.
func (c *OIDCConfig) GetScopes() []string {
	if c.Scopes == "" {
		return []string{"openid", "email", "profile"}
	}
	return strings.Split(c.Scopes, ",")
}

// GetAllowedDomains returns the allowed domains as a slice.
func (c *OIDCConfig) GetAllowedDomains() []string {
	if c.AllowedDomains == "" {
		return nil
	}
	domains := strings.Split(c.AllowedDomains, ",")
	for i := range domains {
		domains[i] = strings.TrimSpace(domains[i])
	}
	return domains
}

// GetSessionSecretBytes returns the session secret as bytes.
func (c *OIDCConfig) GetSessionSecretBytes() ([]byte, error) {
	if c.SessionSecret == "" {
		return nil, fmt.Errorf("OIDC_SESSION_SECRET is required")
	}
	// Try to decode as hex first (64 hex chars = 32 bytes)
	if len(c.SessionSecret) == 64 {
		decoded, err := hex.DecodeString(c.SessionSecret)
		if err == nil {
			return decoded, nil
		}
	}
	// Otherwise use as raw bytes (must be exactly 32 bytes)
	if len(c.SessionSecret) != 32 {
		return nil, fmt.Errorf("OIDC_SESSION_SECRET must be 32 bytes (or 64 hex characters)")
	}
	return []byte(c.SessionSecret), nil
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host string `env:"SERVER_HOST" envDefault:"0.0.0.0"`
	Port int    `env:"SERVER_PORT" envDefault:"8080"`
}

// DatabaseConfig holds database configuration.
type DatabaseConfig struct {
	Driver string `env:"DB_DRIVER" envDefault:"sqlite3"`
	DSN    string `env:"DB_DSN" envDefault:"data/acl-manager.db"`
}

// TailscaleConfig holds Tailscale API configuration.
type TailscaleConfig struct {
	Tailnet  string `env:"TAILSCALE_TAILNET"`
	APIKey   string `env:"TAILSCALE_API_KEY"`
	FileShim string `env:"TAILSCALE_FILE_SHIM"` // Path to file for testing shim (disables real API)
}

// SyncConfig holds sync behavior configuration.
type SyncConfig struct {
	AutoSync        bool          `env:"AUTO_SYNC" envDefault:"true"`
	Debounce        time.Duration `env:"SYNC_DEBOUNCE" envDefault:"5s"`
	BootstrapAPIKey string        `env:"BOOTSTRAP_API_KEY"`
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}

	if err := env.Parse(&cfg.Server); err != nil {
		return nil, fmt.Errorf("parsing server config: %w", err)
	}
	if err := env.Parse(&cfg.Database); err != nil {
		return nil, fmt.Errorf("parsing database config: %w", err)
	}
	if err := env.Parse(&cfg.Tailscale); err != nil {
		return nil, fmt.Errorf("parsing tailscale config: %w", err)
	}
	if err := env.Parse(&cfg.Sync); err != nil {
		return nil, fmt.Errorf("parsing sync config: %w", err)
	}
	if err := env.Parse(&cfg.OIDC); err != nil {
		return nil, fmt.Errorf("parsing oidc config: %w", err)
	}

	return cfg, nil
}

// Addr returns the server address in host:port format.
func (c *ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	// If using file shim, Tailscale credentials are not required
	if c.Tailscale.FileShim == "" {
		if c.Tailscale.Tailnet == "" {
			return fmt.Errorf("TAILSCALE_TAILNET is required (or set TAILSCALE_FILE_SHIM for testing)")
		}
		if c.Tailscale.APIKey == "" {
			return fmt.Errorf("TAILSCALE_API_KEY is required (or set TAILSCALE_FILE_SHIM for testing)")
		}
	}

	// Validate OIDC config when enabled
	if c.OIDC.Enabled {
		if c.OIDC.IssuerURL == "" {
			return fmt.Errorf("OIDC_ISSUER_URL is required when OIDC is enabled")
		}
		if c.OIDC.ClientID == "" {
			return fmt.Errorf("OIDC_CLIENT_ID is required when OIDC is enabled")
		}
		if c.OIDC.ClientSecret == "" {
			return fmt.Errorf("OIDC_CLIENT_SECRET is required when OIDC is enabled")
		}
		if c.OIDC.RedirectURL == "" {
			return fmt.Errorf("OIDC_REDIRECT_URL is required when OIDC is enabled")
		}
		if c.OIDC.SessionSecret == "" {
			return fmt.Errorf("OIDC_SESSION_SECRET is required when OIDC is enabled")
		}
		if _, err := c.OIDC.GetSessionSecretBytes(); err != nil {
			return err
		}
	}

	return nil
}

// UseFileShim returns true if the file shim should be used instead of the real API.
func (c *Config) UseFileShim() bool {
	return c.Tailscale.FileShim != ""
}
