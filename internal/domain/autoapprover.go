package domain

import "time"

// AutoApprover represents auto-approver configuration for routes and exit nodes.
// Auto-approvers are merged additively across stacks.
type AutoApprover struct {
	ID        string    `json:"id" db:"id"`
	StackID   string    `json:"stack_id" db:"stack_id"`
	Type      string    `json:"type" db:"type"` // "routes" or "exitNode"
	Match     string    `json:"match" db:"match"` // Route CIDR or "*" for exit nodes
	Approvers []string  `json:"approvers" db:"-"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// CreateAutoApproverRequest is the request body for creating an auto-approver.
type CreateAutoApproverRequest struct {
	Type      string   `json:"type"`
	Match     string   `json:"match"`
	Approvers []string `json:"approvers"`
}

// UpdateAutoApproverRequest is the request body for updating an auto-approver.
type UpdateAutoApproverRequest struct {
	Approvers []string `json:"approvers"`
}
