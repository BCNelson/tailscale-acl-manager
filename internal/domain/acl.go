package domain

import "time"

// ACLRule represents a network access rule in the Tailscale ACL.
// Rules are ordered by stack priority, then by the order field within each stack.
type ACLRule struct {
	ID           string   `json:"id" db:"id"`
	StackID      string   `json:"stackId" db:"stack_id"`
	Order        int      `json:"order" db:"rule_order"` // Order within stack
	Action       string   `json:"action" db:"action"` // "accept" or "deny" (usually "accept")
	Protocol     string   `json:"protocol,omitempty" db:"protocol"` // Optional protocol filter
	Sources      []string `json:"src" db:"-"` // Stored in separate table
	Destinations []string `json:"dst" db:"-"` // Stored in separate table
	CreatedAt    time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt    time.Time `json:"updatedAt" db:"updated_at"`
}

// CreateACLRuleRequest is the request body for creating an ACL rule.
type CreateACLRuleRequest struct {
	Order        int      `json:"order,omitempty"`
	Action       string   `json:"action"`
	Protocol     string   `json:"protocol,omitempty"`
	Sources      []string `json:"src"`
	Destinations []string `json:"dst"`
}

// UpdateACLRuleRequest is the request body for updating an ACL rule.
type UpdateACLRuleRequest struct {
	Order        *int     `json:"order,omitempty"`
	Action       *string  `json:"action,omitempty"`
	Protocol     *string  `json:"protocol,omitempty"`
	Sources      []string `json:"src,omitempty"`
	Destinations []string `json:"dst,omitempty"`
}
