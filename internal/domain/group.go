package domain

import "time"

// Group represents a Tailscale group (e.g., group:developers).
// Groups from different stacks with the same name will have their members merged.
type Group struct {
	ID        string    `json:"id" db:"id"`
	StackID   string    `json:"stackId" db:"stack_id"`
	Name      string    `json:"name" db:"name"` // e.g., "group:developers"
	Members   []string  `json:"members" db:"-"` // Stored in separate table
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

// CreateGroupRequest is the request body for creating a group.
type CreateGroupRequest struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// UpdateGroupRequest is the request body for updating a group.
type UpdateGroupRequest struct {
	Members []string `json:"members"`
}
