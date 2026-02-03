package domain

import "time"

// Host represents an IP alias in the Tailscale ACL.
// If multiple stacks define the same host name, first-writer wins (by stack priority).
type Host struct {
	ID        string    `json:"id" db:"id"`
	StackID   string    `json:"stack_id" db:"stack_id"`
	Name      string    `json:"name" db:"name"` // Alias name
	Address   string    `json:"address" db:"address"` // IP address or CIDR
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// CreateHostRequest is the request body for creating a host.
type CreateHostRequest struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// UpdateHostRequest is the request body for updating a host.
type UpdateHostRequest struct {
	Address string `json:"address"`
}
