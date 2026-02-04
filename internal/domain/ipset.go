package domain

import "time"

// IPSet represents an IP set (named collection of IP ranges).
// If multiple stacks define the same IP set name, first-writer wins (by stack priority).
type IPSet struct {
	ID        string    `json:"id" db:"id"`
	StackID   string    `json:"stackId" db:"stack_id"`
	Name      string    `json:"name" db:"name"`
	Addresses []string  `json:"addresses" db:"-"` // IP addresses/CIDRs
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

// CreateIPSetRequest is the request body for creating an IP set.
type CreateIPSetRequest struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// UpdateIPSetRequest is the request body for updating an IP set.
type UpdateIPSetRequest struct {
	Addresses []string `json:"addresses"`
}
