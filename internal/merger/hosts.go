package merger

import (
	"context"
)

// mergeHosts merges hosts from all stacks.
// First-writer wins (by stack priority) - if multiple stacks define the same host name,
// the one from the highest priority stack is used.
func (m *Merger) mergeHosts(ctx context.Context) (map[string]string, error) {
	hosts, err := m.store.ListAllHosts(ctx)
	if err != nil {
		return nil, err
	}

	if len(hosts) == 0 {
		return nil, nil
	}

	// Results are already ordered by stack priority, so first occurrence wins
	result := make(map[string]string)
	for _, h := range hosts {
		if _, exists := result[h.Name]; !exists {
			result[h.Name] = h.Address
		}
	}

	return result, nil
}
