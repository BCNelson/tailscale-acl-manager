package domain

import "time"

// APIKey represents an API key for authentication.
// The actual key is only returned once on creation.
type APIKey struct {
	ID         string     `json:"id" db:"id"`
	Name       string     `json:"name" db:"name"`
	KeyHash    string     `json:"-" db:"key_hash"` // Never expose hash
	KeyPrefix  string     `json:"key_prefix" db:"key_prefix"` // First 8 chars for identification
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}

// CreateAPIKeyRequest is the request body for creating an API key.
type CreateAPIKeyRequest struct {
	Name string `json:"name"`
}

// CreateAPIKeyResponse is returned when creating an API key.
// The key is only shown once.
type CreateAPIKeyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"` // Only returned on creation
	KeyPrefix string    `json:"key_prefix"`
	CreatedAt time.Time `json:"created_at"`
}
