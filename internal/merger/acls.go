package merger

import (
	"context"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// mergeACLs merges ACL rules from all stacks.
// Rules are ordered by stack priority, then by rule order within each stack.
func (m *Merger) mergeACLs(ctx context.Context) ([]domain.TailscaleACL, error) {
	rules, err := m.store.ListAllACLRules(ctx)
	if err != nil {
		return nil, err
	}

	if len(rules) == 0 {
		return nil, nil
	}

	// Results are already ordered by stack priority then rule order
	result := make([]domain.TailscaleACL, 0, len(rules))
	for _, r := range rules {
		acl := domain.TailscaleACL{
			Action: r.Action,
			Src:    r.Sources,
			Dst:    r.Destinations,
		}
		if r.Protocol != "" {
			acl.Protocol = r.Protocol
		}
		result = append(result, acl)
	}

	return result, nil
}
