package merger

import (
	"context"
)

// mergeIPSets merges IP sets from all stacks.
// First-writer wins (by stack priority) - if multiple stacks define the same IP set name,
// the one from the highest priority stack is used.
func (m *Merger) mergeIPSets(ctx context.Context) (map[string][]string, error) {
	ipsets, err := m.store.ListAllIPSets(ctx)
	if err != nil {
		return nil, err
	}

	if len(ipsets) == 0 {
		return nil, nil
	}

	// Results are already ordered by stack priority, so first occurrence wins
	result := make(map[string][]string)
	for _, is := range ipsets {
		if _, exists := result[is.Name]; !exists {
			result[is.Name] = is.Addresses
		}
	}

	return result, nil
}
