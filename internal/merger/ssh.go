package merger

import (
	"context"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// mergeSSH merges SSH rules from all stacks.
// SSH rules are ordered by stack priority, then by rule order within each stack.
func (m *Merger) mergeSSH(ctx context.Context) ([]domain.TailscaleSSH, error) {
	rules, err := m.store.ListAllSSHRules(ctx)
	if err != nil {
		return nil, err
	}

	if len(rules) == 0 {
		return nil, nil
	}

	// Results are already ordered by stack priority then rule order
	result := make([]domain.TailscaleSSH, 0, len(rules))
	for _, r := range rules {
		ssh := domain.TailscaleSSH{
			Action: r.Action,
			Src:    r.Sources,
			Dst:    r.Destinations,
			Users:  r.Users,
		}
		if r.CheckPeriod != "" {
			ssh.CheckPeriod = r.CheckPeriod
		}
		result = append(result, ssh)
	}

	return result, nil
}
