package domain

import "time"

// TagOwner defines who can assign a specific tag.
// Tag owners from different stacks with the same tag will have their owners merged.
type TagOwner struct {
	ID        string    `json:"id" db:"id"`
	StackID   string    `json:"stackId" db:"stack_id"`
	Tag       string    `json:"tag" db:"tag"` // e.g., "tag:server"
	Owners    []string  `json:"owners" db:"-"` // Stored in separate table
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

// CreateTagOwnerRequest is the request body for creating a tag owner.
type CreateTagOwnerRequest struct {
	Tag    string   `json:"tag"`
	Owners []string `json:"owners"`
}

// UpdateTagOwnerRequest is the request body for updating a tag owner.
type UpdateTagOwnerRequest struct {
	Owners []string `json:"owners"`
}
