package domain

// StackState represents the complete state of a stack for bulk operations.
// Used for IaC-friendly "replace all" operations.
type StackState struct {
	Groups        []CreateGroupRequest        `json:"groups,omitempty"`
	TagOwners     []CreateTagOwnerRequest     `json:"tagOwners,omitempty"`
	Hosts         []CreateHostRequest         `json:"hosts,omitempty"`
	ACLs          []CreateACLRuleRequest      `json:"acls,omitempty"`
	SSHRules      []CreateSSHRuleRequest      `json:"ssh,omitempty"`
	Grants        []CreateGrantRequest        `json:"grants,omitempty"`
	AutoApprovers []CreateAutoApproverRequest `json:"autoApprovers,omitempty"`
	NodeAttrs     []CreateNodeAttrRequest     `json:"nodeAttrs,omitempty"`
	Postures      []CreatePostureRequest      `json:"postures,omitempty"`
	IPSets        []CreateIPSetRequest        `json:"ipsets,omitempty"`
	Tests         []CreateACLTestRequest      `json:"tests,omitempty"`
}
