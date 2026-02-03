package domain

import "time"

// PolicyVersion represents a versioned snapshot of the rendered ACL policy.
// Used for audit trail and rollback capability.
type PolicyVersion struct {
	ID             string    `json:"id" db:"id"`
	VersionNumber  int       `json:"version_number" db:"version_number"`
	RenderedPolicy string    `json:"rendered_policy" db:"rendered_policy"` // JSON string
	TailscaleETag  string    `json:"tailscale_etag,omitempty" db:"tailscale_etag"`
	PushStatus     string    `json:"push_status" db:"push_status"` // "pending", "success", "failed"
	PushError      string    `json:"push_error,omitempty" db:"push_error"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	PushedAt       *time.Time `json:"pushed_at,omitempty" db:"pushed_at"`
}

// TailscalePolicy represents the complete Tailscale ACL policy structure.
// This is what gets rendered and pushed to Tailscale.
type TailscalePolicy struct {
	Groups        map[string][]string        `json:"groups,omitempty"`
	TagOwners     map[string][]string        `json:"tagOwners,omitempty"`
	Hosts         map[string]string          `json:"hosts,omitempty"`
	ACLs          []TailscaleACL             `json:"acls,omitempty"`
	Grants        []TailscaleGrant           `json:"grants,omitempty"`
	SSH           []TailscaleSSH             `json:"ssh,omitempty"`
	AutoApprovers *TailscaleAutoApprovers    `json:"autoApprovers,omitempty"`
	NodeAttrs     []TailscaleNodeAttr        `json:"nodeAttrs,omitempty"`
	Postures      map[string][]string        `json:"postures,omitempty"`
	IPSets        map[string][]string        `json:"ipsets,omitempty"`
	Tests         []TailscaleTest            `json:"tests,omitempty"`
}

// TailscaleACL is an ACL rule in Tailscale format.
type TailscaleACL struct {
	Action   string   `json:"action"`
	Protocol string   `json:"proto,omitempty"`
	Src      []string `json:"src"`
	Dst      []string `json:"dst"`
}

// TailscaleGrant is a grant in Tailscale format.
type TailscaleGrant struct {
	Src []string               `json:"src"`
	Dst []string               `json:"dst"`
	IP  []string               `json:"ip,omitempty"`
	App map[string][]AppPermission `json:"app,omitempty"`
}

// TailscaleSSH is an SSH rule in Tailscale format.
type TailscaleSSH struct {
	Action      string   `json:"action"`
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Users       []string `json:"users"`
	CheckPeriod string   `json:"checkPeriod,omitempty"`
}

// TailscaleAutoApprovers is the auto-approvers section in Tailscale format.
type TailscaleAutoApprovers struct {
	Routes   map[string][]string `json:"routes,omitempty"`
	ExitNode []string            `json:"exitNode,omitempty"`
}

// TailscaleNodeAttr is a node attribute in Tailscale format.
type TailscaleNodeAttr struct {
	Target []string       `json:"target"`
	Attr   []string       `json:"attr,omitempty"`
	App    map[string]any `json:"app,omitempty"`
}

// TailscaleTest is an ACL test in Tailscale format.
type TailscaleTest struct {
	Src    string   `json:"src"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}

// SyncRequest is used to trigger a manual sync.
type SyncRequest struct {
	Force bool `json:"force,omitempty"` // Force sync even if no changes detected
}

// SyncResponse is returned after a sync operation.
type SyncResponse struct {
	VersionID     string `json:"version_id"`
	VersionNumber int    `json:"version_number"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
}

// RollbackRequest is used to rollback to a previous version.
type RollbackRequest struct {
	VersionID string `json:"version_id"`
}
