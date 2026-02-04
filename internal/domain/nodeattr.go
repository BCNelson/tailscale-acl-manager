package domain

import "time"

// NodeAttr represents node attribute configuration.
// Node attributes are concatenated from all stacks.
type NodeAttr struct {
	ID        string            `json:"id" db:"id"`
	StackID   string            `json:"stackId" db:"stack_id"`
	Order     int               `json:"order" db:"rule_order"`
	Target    []string          `json:"target" db:"-"`
	Attr      []string          `json:"attr,omitempty" db:"-"`
	App       map[string]any    `json:"app,omitempty" db:"-"` // JSON stored as text
	CreatedAt time.Time         `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time         `json:"updatedAt" db:"updated_at"`
}

// CreateNodeAttrRequest is the request body for creating a node attribute.
type CreateNodeAttrRequest struct {
	Order  int              `json:"order,omitempty"`
	Target []string         `json:"target"`
	Attr   []string         `json:"attr,omitempty"`
	App    map[string]any   `json:"app,omitempty"`
}

// UpdateNodeAttrRequest is the request body for updating a node attribute.
type UpdateNodeAttrRequest struct {
	Order  *int             `json:"order,omitempty"`
	Target []string         `json:"target,omitempty"`
	Attr   []string         `json:"attr,omitempty"`
	App    map[string]any   `json:"app,omitempty"`
}
