package domain

import "time"

// Grant represents a capability grant in the Tailscale ACL.
// Grants are ordered by stack priority, then by the order field within each stack.
type Grant struct {
	ID          string   `json:"id" db:"id"`
	StackID     string   `json:"stackId" db:"stack_id"`
	Order       int      `json:"order" db:"rule_order"`
	Sources     []string `json:"src" db:"-"`
	Destinations []string `json:"dst" db:"-"`
	IP          []string `json:"ip,omitempty" db:"-"`
	App         map[string][]AppPermission `json:"app,omitempty" db:"-"`
	CreatedAt   time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time `json:"updatedAt" db:"updated_at"`
}

// AppPermission represents app-specific permissions in a grant.
type AppPermission struct {
	Name string   `json:"name,omitempty"`
	Path string   `json:"path,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

// CreateGrantRequest is the request body for creating a grant.
type CreateGrantRequest struct {
	Order        int      `json:"order,omitempty"`
	Sources      []string `json:"src"`
	Destinations []string `json:"dst"`
	IP           []string `json:"ip,omitempty"`
	App          map[string][]AppPermission `json:"app,omitempty"`
}

// UpdateGrantRequest is the request body for updating a grant.
type UpdateGrantRequest struct {
	Order        *int     `json:"order,omitempty"`
	Sources      []string `json:"src,omitempty"`
	Destinations []string `json:"dst,omitempty"`
	IP           []string `json:"ip,omitempty"`
	App          map[string][]AppPermission `json:"app,omitempty"`
}
