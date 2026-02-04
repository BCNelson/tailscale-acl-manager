package merger_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/merger"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage/memory"
)

func TestMergeGroups_Union(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	// Create two stacks with different priorities
	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	// Create overlapping groups - both stacks define "group:developers"
	group1 := &domain.Group{
		ID:        "g1",
		StackID:   "stack1",
		Name:      "group:developers",
		Members:   []string{"user1@example.com", "user2@example.com"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	group2 := &domain.Group{
		ID:        "g2",
		StackID:   "stack2",
		Name:      "group:developers",
		Members:   []string{"user2@example.com", "user3@example.com"}, // user2 is in both
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	// Stack 1 also has a unique group
	group3 := &domain.Group{
		ID:        "g3",
		StackID:   "stack1",
		Name:      "group:admins",
		Members:   []string{"admin@example.com"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = store.CreateGroup(ctx, group1)
	_ = store.CreateGroup(ctx, group2)
	_ = store.CreateGroup(ctx, group3)

	// Merge
	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Verify groups are merged with union of members
	if len(policy.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(policy.Groups))
	}

	devs := policy.Groups["group:developers"]
	if devs == nil {
		t.Fatal("Expected group:developers to exist")
	}
	sort.Strings(devs)
	expected := []string{"user1@example.com", "user2@example.com", "user3@example.com"}
	sort.Strings(expected)
	if len(devs) != len(expected) {
		t.Errorf("Expected %d members in group:developers, got %d", len(expected), len(devs))
	}
	for i, m := range expected {
		if devs[i] != m {
			t.Errorf("Expected member %s, got %s", m, devs[i])
		}
	}

	admins := policy.Groups["group:admins"]
	if len(admins) != 1 || admins[0] != "admin@example.com" {
		t.Errorf("Expected group:admins with admin@example.com, got %v", admins)
	}
}

func TestMergeTagOwners_Union(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	// Both stacks define owners for tag:server
	to1 := &domain.TagOwner{
		ID:        "to1",
		StackID:   "stack1",
		Tag:       "tag:server",
		Owners:    []string{"group:admins", "user1@example.com"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	to2 := &domain.TagOwner{
		ID:        "to2",
		StackID:   "stack2",
		Tag:       "tag:server",
		Owners:    []string{"group:devops", "user1@example.com"}, // user1 is in both
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = store.CreateTagOwner(ctx, to1)
	_ = store.CreateTagOwner(ctx, to2)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	owners := policy.TagOwners["tag:server"]
	if owners == nil {
		t.Fatal("Expected tag:server owners to exist")
	}
	sort.Strings(owners)
	expected := []string{"group:admins", "group:devops", "user1@example.com"}
	sort.Strings(expected)
	if len(owners) != len(expected) {
		t.Errorf("Expected %d owners, got %d", len(expected), len(owners))
	}
}

func TestMergeHosts_FirstWriterWins(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	// Stack 1 has higher priority (lower number)
	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	// Both stacks define "webserver" with different IPs
	host1 := &domain.Host{
		ID:        "h1",
		StackID:   "stack1",
		Name:      "webserver",
		Address:   "10.0.0.1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	host2 := &domain.Host{
		ID:        "h2",
		StackID:   "stack2",
		Name:      "webserver",
		Address:   "10.0.0.2", // Different IP - should be ignored
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	host3 := &domain.Host{
		ID:        "h3",
		StackID:   "stack2",
		Name:      "database",
		Address:   "10.0.0.3", // Unique to stack2
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = store.CreateHost(ctx, host1)
	_ = store.CreateHost(ctx, host2)
	_ = store.CreateHost(ctx, host3)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// webserver should have stack1's IP (higher priority)
	if policy.Hosts["webserver"] != "10.0.0.1" {
		t.Errorf("Expected webserver to be 10.0.0.1, got %s", policy.Hosts["webserver"])
	}

	// database should exist
	if policy.Hosts["database"] != "10.0.0.3" {
		t.Errorf("Expected database to be 10.0.0.3, got %s", policy.Hosts["database"])
	}
}

func TestMergeACLs_OrderedByPriorityThenOrder(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	// Stack 2 has higher priority (lower number)
	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	// ACL rules in stack1
	rule1 := &domain.ACLRule{
		ID:           "r1",
		StackID:      "stack1",
		Order:        0,
		Action:       "accept",
		Sources:      []string{"group:devs"},
		Destinations: []string{"*:22"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	rule2 := &domain.ACLRule{
		ID:           "r2",
		StackID:      "stack1",
		Order:        1,
		Action:       "accept",
		Sources:      []string{"*"},
		Destinations: []string{"*:443"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// ACL rules in stack2 (higher priority - should come first)
	rule3 := &domain.ACLRule{
		ID:           "r3",
		StackID:      "stack2",
		Order:        0,
		Action:       "accept",
		Sources:      []string{"group:admins"},
		Destinations: []string{"*:*"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	_ = store.CreateACLRule(ctx, rule1)
	_ = store.CreateACLRule(ctx, rule2)
	_ = store.CreateACLRule(ctx, rule3)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	if len(policy.ACLs) != 3 {
		t.Fatalf("Expected 3 ACLs, got %d", len(policy.ACLs))
	}

	// Stack2's rule should come first (higher priority)
	if policy.ACLs[0].Src[0] != "group:admins" {
		t.Errorf("Expected first rule to be from stack2 (group:admins), got %v", policy.ACLs[0].Src)
	}

	// Then stack1's rules in order
	if policy.ACLs[1].Src[0] != "group:devs" {
		t.Errorf("Expected second rule to be group:devs, got %v", policy.ACLs[1].Src)
	}
	if policy.ACLs[2].Src[0] != "*" {
		t.Errorf("Expected third rule to be *, got %v", policy.ACLs[2].Src)
	}
}

func TestMergeSSH_OrderedByPriorityThenOrder(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	ssh1 := &domain.SSHRule{
		ID:           "ssh1",
		StackID:      "stack1",
		Order:        0,
		Action:       "accept",
		Sources:      []string{"group:devs"},
		Destinations: []string{"tag:server"},
		Users:        []string{"root"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	ssh2 := &domain.SSHRule{
		ID:           "ssh2",
		StackID:      "stack2",
		Order:        0,
		Action:       "check",
		Sources:      []string{"group:admins"},
		Destinations: []string{"*"},
		Users:        []string{"autogroup:nonroot"},
		CheckPeriod:  "12h",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	_ = store.CreateSSHRule(ctx, ssh1)
	_ = store.CreateSSHRule(ctx, ssh2)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	if len(policy.SSH) != 2 {
		t.Fatalf("Expected 2 SSH rules, got %d", len(policy.SSH))
	}

	// Stack2's rule should come first (higher priority)
	if policy.SSH[0].Src[0] != "group:admins" {
		t.Errorf("Expected first SSH rule to be from stack2, got %v", policy.SSH[0].Src)
	}
	if policy.SSH[0].CheckPeriod != "12h" {
		t.Errorf("Expected CheckPeriod to be 12h, got %s", policy.SSH[0].CheckPeriod)
	}
}

func TestMergeAutoApprovers_Additive(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	// Both stacks define auto-approvers for the same route
	aa1 := &domain.AutoApprover{
		ID:        "aa1",
		StackID:   "stack1",
		Type:      "routes",
		Match:     "10.0.0.0/8",
		Approvers: []string{"group:network-admins"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	aa2 := &domain.AutoApprover{
		ID:        "aa2",
		StackID:   "stack2",
		Type:      "routes",
		Match:     "10.0.0.0/8",
		Approvers: []string{"tag:router"}, // Different approver for same route
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	aa3 := &domain.AutoApprover{
		ID:        "aa3",
		StackID:   "stack1",
		Type:      "exitNode",
		Match:     "*",
		Approvers: []string{"group:exit-approvers"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = store.CreateAutoApprover(ctx, aa1)
	_ = store.CreateAutoApprover(ctx, aa2)
	_ = store.CreateAutoApprover(ctx, aa3)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	if policy.AutoApprovers == nil {
		t.Fatal("Expected AutoApprovers to be non-nil")
	}

	// Routes for 10.0.0.0/8 should have both approvers
	routeApprovers := policy.AutoApprovers.Routes["10.0.0.0/8"]
	if len(routeApprovers) != 2 {
		t.Errorf("Expected 2 approvers for route, got %d", len(routeApprovers))
	}

	// Exit node approvers
	if len(policy.AutoApprovers.ExitNode) != 1 {
		t.Errorf("Expected 1 exit node approver, got %d", len(policy.AutoApprovers.ExitNode))
	}
}

func TestMergePostures_FirstWriterWins(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	// Both stacks define the same posture
	p1 := &domain.Posture{
		ID:        "p1",
		StackID:   "stack1",
		Name:      "latestMac",
		Rules:     []string{"node:os == 'macos'", "node:osVersion >= '14'"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	p2 := &domain.Posture{
		ID:        "p2",
		StackID:   "stack2",
		Name:      "latestMac",
		Rules:     []string{"node:os == 'macos'"}, // Different rules - should be ignored
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = store.CreatePosture(ctx, p1)
	_ = store.CreatePosture(ctx, p2)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Should use stack1's version (higher priority)
	rules := policy.Postures["latestMac"]
	if len(rules) != 2 {
		t.Errorf("Expected 2 rules from stack1, got %d", len(rules))
	}
}

func TestMergeIPSets_FirstWriterWins(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	// Both stacks define the same IP set
	is1 := &domain.IPSet{
		ID:        "is1",
		StackID:   "stack1",
		Name:      "internal",
		Addresses: []string{"10.0.0.0/8", "192.168.0.0/16"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	is2 := &domain.IPSet{
		ID:        "is2",
		StackID:   "stack2",
		Name:      "internal",
		Addresses: []string{"172.16.0.0/12"}, // Different - should be ignored
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = store.CreateIPSet(ctx, is1)
	_ = store.CreateIPSet(ctx, is2)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Should use stack1's version
	addrs := policy.IPSets["internal"]
	if len(addrs) != 2 {
		t.Errorf("Expected 2 addresses from stack1, got %d", len(addrs))
	}
}

func TestMergeTests_Concatenated(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	test1 := &domain.ACLTest{
		ID:        "t1",
		StackID:   "stack1",
		Order:     0,
		Source:    "user1@example.com",
		Accept:    []string{"server:22"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	test2 := &domain.ACLTest{
		ID:        "t2",
		StackID:   "stack2",
		Order:     0,
		Source:    "user2@example.com",
		Deny:      []string{"*:*"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = store.CreateACLTest(ctx, test1)
	_ = store.CreateACLTest(ctx, test2)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	if len(policy.Tests) != 2 {
		t.Fatalf("Expected 2 tests, got %d", len(policy.Tests))
	}

	// Stack2's test should come first (higher priority)
	if policy.Tests[0].Src != "user2@example.com" {
		t.Errorf("Expected first test to be from stack2, got %s", policy.Tests[0].Src)
	}
}

func TestMergeNodeAttrs_Concatenated(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	na1 := &domain.NodeAttr{
		ID:        "na1",
		StackID:   "stack1",
		Order:     0,
		Target:    []string{"tag:server"},
		Attr:      []string{"funnel"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	na2 := &domain.NodeAttr{
		ID:        "na2",
		StackID:   "stack2",
		Order:     0,
		Target:    []string{"*"},
		Attr:      []string{"mullvad"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = store.CreateNodeAttr(ctx, na1)
	_ = store.CreateNodeAttr(ctx, na2)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	if len(policy.NodeAttrs) != 2 {
		t.Fatalf("Expected 2 node attrs, got %d", len(policy.NodeAttrs))
	}

	// Stack2's should come first
	if policy.NodeAttrs[0].Target[0] != "*" {
		t.Errorf("Expected first nodeAttr to be from stack2, got %v", policy.NodeAttrs[0].Target)
	}
}

func TestMergeGrants_OrderedByPriorityThenOrder(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	stack1 := &domain.Stack{ID: "stack1", Name: "Stack 1", Priority: 20, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	stack2 := &domain.Stack{ID: "stack2", Name: "Stack 2", Priority: 10, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = store.CreateStack(ctx, stack1)
	_ = store.CreateStack(ctx, stack2)

	grant1 := &domain.Grant{
		ID:           "grant1",
		StackID:      "stack1",
		Order:        0,
		Sources:      []string{"group:devs"},
		Destinations: []string{"tag:server"},
		IP:           []string{"*"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	grant2 := &domain.Grant{
		ID:           "grant2",
		StackID:      "stack2",
		Order:        0,
		Sources:      []string{"group:admins"},
		Destinations: []string{"*"},
		IP:           []string{"*"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	_ = store.CreateGrant(ctx, grant1)
	_ = store.CreateGrant(ctx, grant2)

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	if len(policy.Grants) != 2 {
		t.Fatalf("Expected 2 grants, got %d", len(policy.Grants))
	}

	// Stack2's grant should come first (higher priority)
	if policy.Grants[0].Src[0] != "group:admins" {
		t.Errorf("Expected first grant to be from stack2, got %v", policy.Grants[0].Src)
	}
}

func TestMergeEmpty(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	m := merger.New(store)
	policy, err := m.Merge(ctx)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// All fields should be nil/empty
	if policy.Groups != nil {
		t.Errorf("Expected Groups to be nil, got %v", policy.Groups)
	}
	if policy.ACLs != nil {
		t.Errorf("Expected ACLs to be nil, got %v", policy.ACLs)
	}
}
