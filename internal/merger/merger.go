package merger

import (
	"context"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
)

// Merger merges ACL resources from multiple stacks into a single Tailscale policy.
type Merger struct {
	store storage.Storage
}

// New creates a new Merger.
func New(store storage.Storage) *Merger {
	return &Merger{store: store}
}

// Merge loads all resources from storage and merges them into a single policy.
func (m *Merger) Merge(ctx context.Context) (*domain.TailscalePolicy, error) {
	policy := &domain.TailscalePolicy{}

	// Merge groups (union of members)
	groups, err := m.mergeGroups(ctx)
	if err != nil {
		return nil, err
	}
	if len(groups) > 0 {
		policy.Groups = groups
	}

	// Merge tag owners (union of owners)
	tagOwners, err := m.mergeTagOwners(ctx)
	if err != nil {
		return nil, err
	}
	if len(tagOwners) > 0 {
		policy.TagOwners = tagOwners
	}

	// Merge hosts (first-writer wins by stack priority)
	hosts, err := m.mergeHosts(ctx)
	if err != nil {
		return nil, err
	}
	if len(hosts) > 0 {
		policy.Hosts = hosts
	}

	// Merge ACLs (ordered by stack priority, then rule order)
	acls, err := m.mergeACLs(ctx)
	if err != nil {
		return nil, err
	}
	if len(acls) > 0 {
		policy.ACLs = acls
	}

	// Merge grants (ordered by stack priority, then rule order)
	grants, err := m.mergeGrants(ctx)
	if err != nil {
		return nil, err
	}
	if len(grants) > 0 {
		policy.Grants = grants
	}

	// Merge SSH rules (ordered by stack priority, then rule order)
	ssh, err := m.mergeSSH(ctx)
	if err != nil {
		return nil, err
	}
	if len(ssh) > 0 {
		policy.SSH = ssh
	}

	// Merge auto approvers (additive merge)
	autoApprovers, err := m.mergeAutoApprovers(ctx)
	if err != nil {
		return nil, err
	}
	if autoApprovers != nil {
		policy.AutoApprovers = autoApprovers
	}

	// Merge node attributes (concatenated)
	nodeAttrs, err := m.mergeNodeAttrs(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodeAttrs) > 0 {
		policy.NodeAttrs = nodeAttrs
	}

	// Merge postures (first-writer wins by stack priority)
	postures, err := m.mergePostures(ctx)
	if err != nil {
		return nil, err
	}
	if len(postures) > 0 {
		policy.Postures = postures
	}

	// Merge IP sets (first-writer wins by stack priority)
	ipsets, err := m.mergeIPSets(ctx)
	if err != nil {
		return nil, err
	}
	if len(ipsets) > 0 {
		policy.IPSets = ipsets
	}

	// Merge tests (concatenated)
	tests, err := m.mergeTests(ctx)
	if err != nil {
		return nil, err
	}
	if len(tests) > 0 {
		policy.Tests = tests
	}

	return policy, nil
}
