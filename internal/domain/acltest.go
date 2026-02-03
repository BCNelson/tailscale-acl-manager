package domain

import "time"

// ACLTest represents an ACL test case.
// Tests from all stacks are concatenated together.
type ACLTest struct {
	ID         string   `json:"id" db:"id"`
	StackID    string   `json:"stack_id" db:"stack_id"`
	Order      int      `json:"order" db:"rule_order"`
	Source     string   `json:"src" db:"src"`
	Accept     []string `json:"accept,omitempty" db:"-"`
	Deny       []string `json:"deny,omitempty" db:"-"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// CreateACLTestRequest is the request body for creating an ACL test.
type CreateACLTestRequest struct {
	Order  int      `json:"order,omitempty"`
	Source string   `json:"src"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}

// UpdateACLTestRequest is the request body for updating an ACL test.
type UpdateACLTestRequest struct {
	Order  *int     `json:"order,omitempty"`
	Source *string  `json:"src,omitempty"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}
