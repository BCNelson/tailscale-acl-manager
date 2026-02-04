package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/api"
	"github.com/bcnelson/tailscale-acl-manager/internal/auth"
	"github.com/bcnelson/tailscale-acl-manager/internal/config"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage/sql"
	"github.com/bcnelson/tailscale-acl-manager/internal/tailscale"
	"github.com/bcnelson/tailscale-acl-manager/internal/web"
)

// Version is set at build time via -ldflags
var Version = "dev"

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Create data directory if needed (for SQLite)
	if cfg.Database.Driver == "sqlite3" {
		dir := "data"
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
	}

	// Initialize storage
	store, err := sql.New(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// Initialize Tailscale client (or file shim for testing)
	var tsClient tailscale.PolicyClient
	if cfg.UseFileShim() {
		log.Printf("Using file shim for Tailscale API: %s", cfg.Tailscale.FileShim)
		tsClient = tailscale.NewFileShim(cfg.Tailscale.FileShim)
	} else {
		client, err := tailscale.New(cfg.Tailscale.APIKey, cfg.Tailscale.Tailnet)
		if err != nil {
			log.Fatalf("Failed to initialize Tailscale client: %v", err)
		}
		tsClient = client
	}

	// Initialize sync service
	syncService := service.NewSyncService(
		store,
		tsClient,
		cfg.Sync.Debounce,
		cfg.Sync.AutoSync,
	)

	// Initialize OIDC if enabled
	var oidcComponents *web.OIDCComponents
	if cfg.OIDC.Enabled {
		log.Printf("Initializing OIDC with issuer: %s", cfg.OIDC.IssuerURL)

		// Determine if we should use secure cookies (based on redirect URL)
		secure := strings.HasPrefix(cfg.OIDC.RedirectURL, "https://")

		// Get session secret
		sessionKey, err := cfg.OIDC.GetSessionSecretBytes()
		if err != nil {
			log.Fatalf("Failed to get OIDC session secret: %v", err)
		}

		// Create OIDC provider
		oidcProvider, err := auth.NewOIDCProvider(
			context.Background(),
			cfg.OIDC.IssuerURL,
			cfg.OIDC.ClientID,
			cfg.OIDC.ClientSecret,
			cfg.OIDC.RedirectURL,
			cfg.OIDC.GetScopes(),
			cfg.OIDC.GetAllowedDomains(),
		)
		if err != nil {
			log.Fatalf("Failed to initialize OIDC provider: %v", err)
		}

		// Create session manager
		sessionManager, err := auth.NewSessionManager(sessionKey, cfg.OIDC.SessionDuration, secure)
		if err != nil {
			log.Fatalf("Failed to initialize session manager: %v", err)
		}

		// Create state store
		stateStore, err := auth.NewStateStore(sessionKey, secure)
		if err != nil {
			log.Fatalf("Failed to initialize state store: %v", err)
		}

		oidcComponents = &web.OIDCComponents{
			Provider:       oidcProvider,
			SessionManager: sessionManager,
			StateStore:     stateStore,
		}

		log.Printf("OIDC authentication enabled")
	}

	// Create router
	router := api.NewRouter(store, syncService, cfg.Sync.BootstrapAPIKey, &cfg.OIDC, oidcComponents)

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting Tailscale ACL Manager %s on http://%s", Version, cfg.Server.Addr())
	log.Printf("Press Ctrl+C to stop")

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}
