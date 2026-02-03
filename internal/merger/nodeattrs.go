package merger

import (
	"context"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// mergeNodeAttrs merges node attributes from all stacks.
// Node attributes are concatenated from all stacks, ordered by stack priority then rule order.
func (m *Merger) mergeNodeAttrs(ctx context.Context) ([]domain.TailscaleNodeAttr, error) {
	nodeAttrs, err := m.store.ListAllNodeAttrs(ctx)
	if err != nil {
		return nil, err
	}

	if len(nodeAttrs) == 0 {
		return nil, nil
	}

	// Results are already ordered by stack priority then rule order
	result := make([]domain.TailscaleNodeAttr, 0, len(nodeAttrs))
	for _, na := range nodeAttrs {
		attr := domain.TailscaleNodeAttr{
			Target: na.Target,
		}
		if len(na.Attr) > 0 {
			attr.Attr = na.Attr
		}
		if len(na.App) > 0 {
			attr.App = na.App
		}
		result = append(result, attr)
	}

	return result, nil
}
