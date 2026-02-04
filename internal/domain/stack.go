package domain

import "time"

// Stack represents an IaC deployment or rule owner.
// Each stack contains a set of ACL resources that will be merged together.
type Stack struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Priority    int       `json:"priority" db:"priority"` // Lower = higher priority
	CreatedAt   time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time `json:"updatedAt" db:"updated_at"`
}

// CreateStackRequest is the request body for creating a stack.
type CreateStackRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Priority    int    `json:"priority,omitempty"`
}

// UpdateStackRequest is the request body for updating a stack.
type UpdateStackRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Priority    *int    `json:"priority,omitempty"`
}
