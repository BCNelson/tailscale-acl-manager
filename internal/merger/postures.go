package merger

import (
	"context"
)

// mergePostures merges postures from all stacks.
// First-writer wins (by stack priority) - if multiple stacks define the same posture name,
// the one from the highest priority stack is used.
func (m *Merger) mergePostures(ctx context.Context) (map[string][]string, error) {
	postures, err := m.store.ListAllPostures(ctx)
	if err != nil {
		return nil, err
	}

	if len(postures) == 0 {
		return nil, nil
	}

	// Results are already ordered by stack priority, so first occurrence wins
	result := make(map[string][]string)
	for _, p := range postures {
		if _, exists := result[p.Name]; !exists {
			result[p.Name] = p.Rules
		}
	}

	return result, nil
}
