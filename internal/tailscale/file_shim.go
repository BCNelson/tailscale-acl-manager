package tailscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// FileShim is a testing implementation that writes policies to a file.
type FileShim struct {
	filePath string
	mu       sync.RWMutex
	etag     string
}

// Ensure FileShim implements PolicyClient.
var _ PolicyClient = (*FileShim)(nil)

// NewFileShim creates a new file-based shim for testing.
func NewFileShim(filePath string) *FileShim {
	return &FileShim{
		filePath: filePath,
		etag:     generateETag(nil),
	}
}

// GetPolicy reads the current policy from the file.
func (f *FileShim) GetPolicy(ctx context.Context) (*domain.TailscalePolicy, string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	data, err := os.ReadFile(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty policy if file doesn't exist
			return &domain.TailscalePolicy{}, f.etag, nil
		}
		return nil, "", fmt.Errorf("reading policy file: %w", err)
	}

	var policy domain.TailscalePolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, "", fmt.Errorf("parsing policy file: %w", err)
	}

	return &policy, f.etag, nil
}

// SetPolicy writes the policy to the file.
func (f *FileShim) SetPolicy(ctx context.Context, policy *domain.TailscalePolicy, etag string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check ETag for optimistic locking (if provided)
	if etag != "" && etag != f.etag {
		return "", fmt.Errorf("etag mismatch: expected %s, got %s", f.etag, etag)
	}

	// Marshal with indentation for readability
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling policy: %w", err)
	}

	// Write to file
	if err := os.WriteFile(f.filePath, data, 0644); err != nil {
		return "", fmt.Errorf("writing policy file: %w", err)
	}

	// Generate new ETag
	f.etag = generateETag(data)

	log.Printf("[FileShim] Policy written to %s (etag: %s)", f.filePath, f.etag[:12])

	return f.etag, nil
}

// ValidatePolicy validates the policy (always succeeds for the shim).
func (f *FileShim) ValidatePolicy(ctx context.Context, policy *domain.TailscalePolicy) error {
	// Basic validation - just ensure it can be marshaled
	_, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}

	log.Printf("[FileShim] Policy validated successfully")
	return nil
}

// generateETag creates an ETag from the policy data.
func generateETag(data []byte) string {
	if data == nil {
		data = []byte(time.Now().String())
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
