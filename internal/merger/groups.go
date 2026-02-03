package merger

import (
	"context"
)

// mergeGroups merges groups from all stacks.
// Groups with the same name have their members merged (union).
func (m *Merger) mergeGroups(ctx context.Context) (map[string][]string, error) {
	groups, err := m.store.ListAllGroups(ctx)
	if err != nil {
		return nil, err
	}

	if len(groups) == 0 {
		return nil, nil
	}

	// Group by name, union members
	result := make(map[string][]string)
	memberSet := make(map[string]map[string]bool)

	for _, g := range groups {
		if _, ok := memberSet[g.Name]; !ok {
			memberSet[g.Name] = make(map[string]bool)
		}
		for _, member := range g.Members {
			memberSet[g.Name][member] = true
		}
	}

	// Convert sets to slices
	for name, members := range memberSet {
		slice := make([]string, 0, len(members))
		for member := range members {
			slice = append(slice, member)
		}
		result[name] = slice
	}

	return result, nil
}
