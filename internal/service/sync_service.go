package service

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/merger"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/bcnelson/tailscale-acl-manager/internal/tailscale"
	"github.com/google/uuid"
)

// SyncService handles syncing the merged policy to Tailscale.
type SyncService struct {
	store    storage.Storage
	merger   *merger.Merger
	client   tailscale.PolicyClient
	debounce time.Duration
	autoSync bool

	mu          sync.Mutex
	syncTimer   *time.Timer
	syncPending bool
}

// NewSyncService creates a new SyncService.
func NewSyncService(store storage.Storage, client tailscale.PolicyClient, debounce time.Duration, autoSync bool) *SyncService {
	return &SyncService{
		store:    store,
		merger:   merger.New(store),
		client:   client,
		debounce: debounce,
		autoSync: autoSync,
	}
}

// TriggerSync triggers a debounced sync operation.
// Multiple triggers within the debounce period will result in a single sync.
func (s *SyncService) TriggerSync() {
	if !s.autoSync {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Cancel existing timer
	if s.syncTimer != nil {
		s.syncTimer.Stop()
	}

	s.syncPending = true
	s.syncTimer = time.AfterFunc(s.debounce, func() {
		s.mu.Lock()
		s.syncPending = false
		s.mu.Unlock()

		ctx := context.Background()
		if _, err := s.doSync(ctx); err != nil {
			log.Printf("Auto-sync failed: %v", err)
		}
	})
}

// GetMergedPolicy returns the current merged policy without syncing.
func (s *SyncService) GetMergedPolicy(ctx context.Context) (*domain.TailscalePolicy, error) {
	return s.merger.Merge(ctx)
}

// ForceSync forces an immediate sync to Tailscale.
func (s *SyncService) ForceSync(ctx context.Context) (*domain.SyncResponse, error) {
	s.mu.Lock()
	// Cancel any pending debounced sync
	if s.syncTimer != nil {
		s.syncTimer.Stop()
	}
	s.syncPending = false
	s.mu.Unlock()

	return s.doSync(ctx)
}

// doSync performs the actual sync operation.
func (s *SyncService) doSync(ctx context.Context) (*domain.SyncResponse, error) {
	// Merge the policy
	policy, err := s.merger.Merge(ctx)
	if err != nil {
		return nil, err
	}

	// Render to JSON
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}

	// Get next version number
	nextVersion := 1
	latestVersion, err := s.store.GetLatestPolicyVersion(ctx)
	if err == nil {
		nextVersion = latestVersion.VersionNumber + 1
	} else if err != domain.ErrNotFound {
		return nil, err
	}

	// Create version record
	version := &domain.PolicyVersion{
		ID:             uuid.New().String(),
		VersionNumber:  nextVersion,
		RenderedPolicy: string(policyJSON),
		PushStatus:     "pending",
		CreatedAt:      time.Now(),
	}

	if err := s.store.CreatePolicyVersion(ctx, version); err != nil {
		return nil, err
	}

	// Get current ETag for optimistic locking
	_, currentETag, err := s.client.GetPolicy(ctx)
	if err != nil {
		// If we can't get the current policy, proceed without ETag
		log.Printf("Warning: Could not get current policy ETag: %v", err)
		currentETag = ""
	}

	// Push to Tailscale
	now := time.Now()
	newETag, err := s.client.SetPolicy(ctx, policy, currentETag)
	if err != nil {
		// Record failure
		version.PushStatus = "failed"
		version.PushError = err.Error()
		version.PushedAt = &now
		_ = s.store.UpdatePolicyVersion(ctx, version)

		return &domain.SyncResponse{
			VersionID:     version.ID,
			VersionNumber: version.VersionNumber,
			Status:        "failed",
			Error:         err.Error(),
		}, nil
	}

	// Record success
	version.PushStatus = "success"
	version.TailscaleETag = newETag
	version.PushedAt = &now
	if err := s.store.UpdatePolicyVersion(ctx, version); err != nil {
		log.Printf("Warning: Failed to update version record: %v", err)
	}

	return &domain.SyncResponse{
		VersionID:     version.ID,
		VersionNumber: version.VersionNumber,
		Status:        "success",
	}, nil
}

// Rollback rolls back to a previous policy version.
func (s *SyncService) Rollback(ctx context.Context, versionID string) (*domain.SyncResponse, error) {
	// Get the version to rollback to
	version, err := s.store.GetPolicyVersion(ctx, versionID)
	if err != nil {
		return nil, err
	}

	// Parse the rendered policy
	var policy domain.TailscalePolicy
	if err := json.Unmarshal([]byte(version.RenderedPolicy), &policy); err != nil {
		return nil, err
	}

	// Get next version number
	nextVersion := 1
	latestVersion, err := s.store.GetLatestPolicyVersion(ctx)
	if err == nil {
		nextVersion = latestVersion.VersionNumber + 1
	} else if err != domain.ErrNotFound {
		return nil, err
	}

	// Create new version record for the rollback
	newVersion := &domain.PolicyVersion{
		ID:             uuid.New().String(),
		VersionNumber:  nextVersion,
		RenderedPolicy: version.RenderedPolicy,
		PushStatus:     "pending",
		CreatedAt:      time.Now(),
	}

	if err := s.store.CreatePolicyVersion(ctx, newVersion); err != nil {
		return nil, err
	}

	// Get current ETag
	_, currentETag, err := s.client.GetPolicy(ctx)
	if err != nil {
		currentETag = ""
	}

	// Push to Tailscale
	now := time.Now()
	newETag, err := s.client.SetPolicy(ctx, &policy, currentETag)
	if err != nil {
		newVersion.PushStatus = "failed"
		newVersion.PushError = err.Error()
		newVersion.PushedAt = &now
		_ = s.store.UpdatePolicyVersion(ctx, newVersion)

		return &domain.SyncResponse{
			VersionID:     newVersion.ID,
			VersionNumber: newVersion.VersionNumber,
			Status:        "failed",
			Error:         err.Error(),
		}, nil
	}

	newVersion.PushStatus = "success"
	newVersion.TailscaleETag = newETag
	newVersion.PushedAt = &now
	_ = s.store.UpdatePolicyVersion(ctx, newVersion)

	return &domain.SyncResponse{
		VersionID:     newVersion.ID,
		VersionNumber: newVersion.VersionNumber,
		Status:        "success",
	}, nil
}
