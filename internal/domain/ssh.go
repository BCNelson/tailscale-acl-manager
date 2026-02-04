package domain

import "time"

// SSHRule represents an SSH access rule in the Tailscale ACL.
// SSH rules are ordered by stack priority, then by the order field within each stack.
type SSHRule struct {
	ID          string   `json:"id" db:"id"`
	StackID     string   `json:"stackId" db:"stack_id"`
	Order       int      `json:"order" db:"rule_order"`
	Action      string   `json:"action" db:"action"` // "accept", "check"
	Sources     []string `json:"src" db:"-"`
	Destinations []string `json:"dst" db:"-"`
	Users       []string `json:"users" db:"-"`
	CheckPeriod string   `json:"checkPeriod,omitempty" db:"check_period"`
	CreatedAt   time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time `json:"updatedAt" db:"updated_at"`
}

// CreateSSHRuleRequest is the request body for creating an SSH rule.
type CreateSSHRuleRequest struct {
	Order        int      `json:"order,omitempty"`
	Action       string   `json:"action"`
	Sources      []string `json:"src"`
	Destinations []string `json:"dst"`
	Users        []string `json:"users"`
	CheckPeriod  string   `json:"checkPeriod,omitempty"`
}

// UpdateSSHRuleRequest is the request body for updating an SSH rule.
type UpdateSSHRuleRequest struct {
	Order        *int     `json:"order,omitempty"`
	Action       *string  `json:"action,omitempty"`
	Sources      []string `json:"src,omitempty"`
	Destinations []string `json:"dst,omitempty"`
	Users        []string `json:"users,omitempty"`
	CheckPeriod  *string  `json:"checkPeriod,omitempty"`
}
