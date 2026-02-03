package merger

import (
	"context"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// mergeTests merges ACL tests from all stacks.
// Tests are concatenated from all stacks, ordered by stack priority then rule order.
func (m *Merger) mergeTests(ctx context.Context) ([]domain.TailscaleTest, error) {
	tests, err := m.store.ListAllACLTests(ctx)
	if err != nil {
		return nil, err
	}

	if len(tests) == 0 {
		return nil, nil
	}

	// Results are already ordered by stack priority then rule order
	result := make([]domain.TailscaleTest, 0, len(tests))
	for _, t := range tests {
		test := domain.TailscaleTest{
			Src: t.Source,
		}
		if len(t.Accept) > 0 {
			test.Accept = t.Accept
		}
		if len(t.Deny) > 0 {
			test.Deny = t.Deny
		}
		result = append(result, test)
	}

	return result, nil
}
