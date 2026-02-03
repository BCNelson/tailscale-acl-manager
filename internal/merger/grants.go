package merger

import (
	"context"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// mergeGrants merges grants from all stacks.
// Grants are ordered by stack priority, then by rule order within each stack.
func (m *Merger) mergeGrants(ctx context.Context) ([]domain.TailscaleGrant, error) {
	grants, err := m.store.ListAllGrants(ctx)
	if err != nil {
		return nil, err
	}

	if len(grants) == 0 {
		return nil, nil
	}

	// Results are already ordered by stack priority then rule order
	result := make([]domain.TailscaleGrant, 0, len(grants))
	for _, g := range grants {
		grant := domain.TailscaleGrant{
			Src: g.Sources,
			Dst: g.Destinations,
		}
		if len(g.IP) > 0 {
			grant.IP = g.IP
		}
		if len(g.App) > 0 {
			grant.App = g.App
		}
		result = append(result, grant)
	}

	return result, nil
}
