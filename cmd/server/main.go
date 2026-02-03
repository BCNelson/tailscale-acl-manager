package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/api"
	"github.com/bcnelson/tailscale-acl-manager/internal/config"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage/sql"
	"github.com/bcnelson/tailscale-acl-manager/internal/tailscale"
)

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

	// Create router
	router := api.NewRouter(store, syncService, cfg.Sync.BootstrapAPIKey)

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting Tailscale ACL Manager on http://%s", cfg.Server.Addr())
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
