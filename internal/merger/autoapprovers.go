package merger

import (
	"context"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// mergeAutoApprovers merges auto approvers from all stacks.
// Auto approvers are merged additively - all approvers for a route are combined.
func (m *Merger) mergeAutoApprovers(ctx context.Context) (*domain.TailscaleAutoApprovers, error) {
	autoApprovers, err := m.store.ListAllAutoApprovers(ctx)
	if err != nil {
		return nil, err
	}

	if len(autoApprovers) == 0 {
		return nil, nil
	}

	result := &domain.TailscaleAutoApprovers{
		Routes: make(map[string][]string),
	}

	// Track approvers with sets to avoid duplicates
	routeApproverSets := make(map[string]map[string]bool)
	exitNodeApproverSet := make(map[string]bool)

	for _, aa := range autoApprovers {
		if aa.Type == "routes" {
			if _, ok := routeApproverSets[aa.Match]; !ok {
				routeApproverSets[aa.Match] = make(map[string]bool)
			}
			for _, approver := range aa.Approvers {
				routeApproverSets[aa.Match][approver] = true
			}
		} else if aa.Type == "exitNode" {
			for _, approver := range aa.Approvers {
				exitNodeApproverSet[approver] = true
			}
		}
	}

	// Convert sets to slices
	for route, approverSet := range routeApproverSets {
		approvers := make([]string, 0, len(approverSet))
		for approver := range approverSet {
			approvers = append(approvers, approver)
		}
		result.Routes[route] = approvers
	}

	if len(exitNodeApproverSet) > 0 {
		exitNodeApprovers := make([]string, 0, len(exitNodeApproverSet))
		for approver := range exitNodeApproverSet {
			exitNodeApprovers = append(exitNodeApprovers, approver)
		}
		result.ExitNode = exitNodeApprovers
	}

	// Return nil if nothing was added
	if len(result.Routes) == 0 && len(result.ExitNode) == 0 {
		return nil, nil
	}

	return result, nil
}
