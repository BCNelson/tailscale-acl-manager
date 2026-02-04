package domain

import "time"

// Posture represents device posture configuration.
// If multiple stacks define the same posture name, first-writer wins (by stack priority).
type Posture struct {
	ID        string    `json:"id" db:"id"`
	StackID   string    `json:"stackId" db:"stack_id"`
	Name      string    `json:"name" db:"name"`
	Rules     []string  `json:"rules" db:"-"` // Posture check expressions
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

// CreatePostureRequest is the request body for creating a posture.
type CreatePostureRequest struct {
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

// UpdatePostureRequest is the request body for updating a posture.
type UpdatePostureRequest struct {
	Rules []string `json:"rules"`
}
