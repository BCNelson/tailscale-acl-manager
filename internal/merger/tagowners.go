package merger

import (
	"context"
)

// mergeTagOwners merges tag owners from all stacks.
// Tag owners with the same tag have their owners merged (union).
func (m *Merger) mergeTagOwners(ctx context.Context) (map[string][]string, error) {
	tagOwners, err := m.store.ListAllTagOwners(ctx)
	if err != nil {
		return nil, err
	}

	if len(tagOwners) == 0 {
		return nil, nil
	}

	// Group by tag, union owners
	result := make(map[string][]string)
	ownerSet := make(map[string]map[string]bool)

	for _, to := range tagOwners {
		if _, ok := ownerSet[to.Tag]; !ok {
			ownerSet[to.Tag] = make(map[string]bool)
		}
		for _, owner := range to.Owners {
			ownerSet[to.Tag][owner] = true
		}
	}

	// Convert sets to slices
	for tag, owners := range ownerSet {
		slice := make([]string, 0, len(owners))
		for owner := range owners {
			slice = append(slice, owner)
		}
		result[tag] = slice
	}

	return result, nil
}
