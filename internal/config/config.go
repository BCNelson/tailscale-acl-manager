package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v9"
)

// Config holds all configuration for the application.
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Tailscale TailscaleConfig
	Sync      SyncConfig
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

	return cfg, nil
}

// Addr returns the server address in host:port format.
func (c *ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	// If using file shim, Tailscale credentials are not required
	if c.Tailscale.FileShim != "" {
		return nil
	}

	if c.Tailscale.Tailnet == "" {
		return fmt.Errorf("TAILSCALE_TAILNET is required (or set TAILSCALE_FILE_SHIM for testing)")
	}
	if c.Tailscale.APIKey == "" {
		return fmt.Errorf("TAILSCALE_API_KEY is required (or set TAILSCALE_FILE_SHIM for testing)")
	}
	return nil
}

// UseFileShim returns true if the file shim should be used instead of the real API.
func (c *Config) UseFileShim() bool {
	return c.Tailscale.FileShim != ""
}
