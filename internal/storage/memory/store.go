package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
)

// Store is an in-memory implementation of the storage interface for testing.
type Store struct {
	mu sync.RWMutex

	apiKeys        map[string]*domain.APIKey
	stacks         map[string]*domain.Stack
	groups         map[string]*domain.Group         // key: stackID:name
	tagOwners      map[string]*domain.TagOwner      // key: stackID:tag
	hosts          map[string]*domain.Host          // key: stackID:name
	aclRules       map[string]*domain.ACLRule       // key: id
	sshRules       map[string]*domain.SSHRule       // key: id
	grants         map[string]*domain.Grant         // key: id
	autoApprovers  map[string]*domain.AutoApprover  // key: id
	nodeAttrs      map[string]*domain.NodeAttr      // key: id
	postures       map[string]*domain.Posture       // key: stackID:name
	ipsets         map[string]*domain.IPSet         // key: stackID:name
	aclTests       map[string]*domain.ACLTest       // key: id
	policyVersions map[string]*domain.PolicyVersion // key: id
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		apiKeys:        make(map[string]*domain.APIKey),
		stacks:         make(map[string]*domain.Stack),
		groups:         make(map[string]*domain.Group),
		tagOwners:      make(map[string]*domain.TagOwner),
		hosts:          make(map[string]*domain.Host),
		aclRules:       make(map[string]*domain.ACLRule),
		sshRules:       make(map[string]*domain.SSHRule),
		grants:         make(map[string]*domain.Grant),
		autoApprovers:  make(map[string]*domain.AutoApprover),
		nodeAttrs:      make(map[string]*domain.NodeAttr),
		postures:       make(map[string]*domain.Posture),
		ipsets:         make(map[string]*domain.IPSet),
		aclTests:       make(map[string]*domain.ACLTest),
		policyVersions: make(map[string]*domain.PolicyVersion),
	}
}

func (s *Store) Close() error { return nil }

func (s *Store) BeginTx(ctx context.Context) (storage.Transaction, error) {
	return &Tx{store: s}, nil
}

// Tx is a no-op transaction for in-memory store.
type Tx struct {
	store *Store
}

func (t *Tx) Commit() error   { return nil }
func (t *Tx) Rollback() error { return nil }
func (t *Tx) Close() error    { return nil }
func (t *Tx) BeginTx(ctx context.Context) (storage.Transaction, error) {
	return nil, domain.ErrInvalidInput
}

// Forward all Tx methods to the underlying store
func (t *Tx) CreateAPIKey(ctx context.Context, key *domain.APIKey) error {
	return t.store.CreateAPIKey(ctx, key)
}
func (t *Tx) GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	return t.store.GetAPIKeyByHash(ctx, keyHash)
}
func (t *Tx) ListAPIKeys(ctx context.Context) ([]*domain.APIKey, error) {
	return t.store.ListAPIKeys(ctx)
}
func (t *Tx) DeleteAPIKey(ctx context.Context, id string) error {
	return t.store.DeleteAPIKey(ctx, id)
}
func (t *Tx) UpdateAPIKeyLastUsed(ctx context.Context, id string) error {
	return t.store.UpdateAPIKeyLastUsed(ctx, id)
}
func (t *Tx) CountAPIKeys(ctx context.Context) (int, error) {
	return t.store.CountAPIKeys(ctx)
}
func (t *Tx) CreateStack(ctx context.Context, stack *domain.Stack) error {
	return t.store.CreateStack(ctx, stack)
}
func (t *Tx) GetStack(ctx context.Context, id string) (*domain.Stack, error) {
	return t.store.GetStack(ctx, id)
}
func (t *Tx) GetStackByName(ctx context.Context, name string) (*domain.Stack, error) {
	return t.store.GetStackByName(ctx, name)
}
func (t *Tx) ListStacks(ctx context.Context) ([]*domain.Stack, error) {
	return t.store.ListStacks(ctx)
}
func (t *Tx) UpdateStack(ctx context.Context, stack *domain.Stack) error {
	return t.store.UpdateStack(ctx, stack)
}
func (t *Tx) DeleteStack(ctx context.Context, id string) error {
	return t.store.DeleteStack(ctx, id)
}
func (t *Tx) CreateGroup(ctx context.Context, group *domain.Group) error {
	return t.store.CreateGroup(ctx, group)
}
func (t *Tx) GetGroup(ctx context.Context, stackID, name string) (*domain.Group, error) {
	return t.store.GetGroup(ctx, stackID, name)
}
func (t *Tx) ListGroups(ctx context.Context, stackID string) ([]*domain.Group, error) {
	return t.store.ListGroups(ctx, stackID)
}
func (t *Tx) ListAllGroups(ctx context.Context) ([]*domain.Group, error) {
	return t.store.ListAllGroups(ctx)
}
func (t *Tx) UpdateGroup(ctx context.Context, group *domain.Group) error {
	return t.store.UpdateGroup(ctx, group)
}
func (t *Tx) DeleteGroup(ctx context.Context, stackID, name string) error {
	return t.store.DeleteGroup(ctx, stackID, name)
}
func (t *Tx) GetGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	return t.store.GetGroupByID(ctx, id)
}
func (t *Tx) DeleteGroupByID(ctx context.Context, id string) error {
	return t.store.DeleteGroupByID(ctx, id)
}
func (t *Tx) DeleteAllGroupsForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllGroupsForStack(ctx, stackID)
}
func (t *Tx) CreateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error {
	return t.store.CreateTagOwner(ctx, tagOwner)
}
func (t *Tx) GetTagOwner(ctx context.Context, stackID, tag string) (*domain.TagOwner, error) {
	return t.store.GetTagOwner(ctx, stackID, tag)
}
func (t *Tx) ListTagOwners(ctx context.Context, stackID string) ([]*domain.TagOwner, error) {
	return t.store.ListTagOwners(ctx, stackID)
}
func (t *Tx) ListAllTagOwners(ctx context.Context) ([]*domain.TagOwner, error) {
	return t.store.ListAllTagOwners(ctx)
}
func (t *Tx) UpdateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error {
	return t.store.UpdateTagOwner(ctx, tagOwner)
}
func (t *Tx) DeleteTagOwner(ctx context.Context, stackID, tag string) error {
	return t.store.DeleteTagOwner(ctx, stackID, tag)
}
func (t *Tx) GetTagOwnerByID(ctx context.Context, id string) (*domain.TagOwner, error) {
	return t.store.GetTagOwnerByID(ctx, id)
}
func (t *Tx) DeleteTagOwnerByID(ctx context.Context, id string) error {
	return t.store.DeleteTagOwnerByID(ctx, id)
}
func (t *Tx) DeleteAllTagOwnersForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllTagOwnersForStack(ctx, stackID)
}
func (t *Tx) CreateHost(ctx context.Context, host *domain.Host) error {
	return t.store.CreateHost(ctx, host)
}
func (t *Tx) GetHost(ctx context.Context, stackID, name string) (*domain.Host, error) {
	return t.store.GetHost(ctx, stackID, name)
}
func (t *Tx) ListHosts(ctx context.Context, stackID string) ([]*domain.Host, error) {
	return t.store.ListHosts(ctx, stackID)
}
func (t *Tx) ListAllHosts(ctx context.Context) ([]*domain.Host, error) {
	return t.store.ListAllHosts(ctx)
}
func (t *Tx) UpdateHost(ctx context.Context, host *domain.Host) error {
	return t.store.UpdateHost(ctx, host)
}
func (t *Tx) DeleteHost(ctx context.Context, stackID, name string) error {
	return t.store.DeleteHost(ctx, stackID, name)
}
func (t *Tx) GetHostByID(ctx context.Context, id string) (*domain.Host, error) {
	return t.store.GetHostByID(ctx, id)
}
func (t *Tx) DeleteHostByID(ctx context.Context, id string) error {
	return t.store.DeleteHostByID(ctx, id)
}
func (t *Tx) DeleteAllHostsForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllHostsForStack(ctx, stackID)
}
func (t *Tx) CreateACLRule(ctx context.Context, rule *domain.ACLRule) error {
	return t.store.CreateACLRule(ctx, rule)
}
func (t *Tx) GetACLRule(ctx context.Context, id string) (*domain.ACLRule, error) {
	return t.store.GetACLRule(ctx, id)
}
func (t *Tx) ListACLRules(ctx context.Context, stackID string) ([]*domain.ACLRule, error) {
	return t.store.ListACLRules(ctx, stackID)
}
func (t *Tx) ListAllACLRules(ctx context.Context) ([]*domain.ACLRule, error) {
	return t.store.ListAllACLRules(ctx)
}
func (t *Tx) UpdateACLRule(ctx context.Context, rule *domain.ACLRule) error {
	return t.store.UpdateACLRule(ctx, rule)
}
func (t *Tx) DeleteACLRule(ctx context.Context, id string) error {
	return t.store.DeleteACLRule(ctx, id)
}
func (t *Tx) DeleteAllACLRulesForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllACLRulesForStack(ctx, stackID)
}
func (t *Tx) CreateSSHRule(ctx context.Context, rule *domain.SSHRule) error {
	return t.store.CreateSSHRule(ctx, rule)
}
func (t *Tx) GetSSHRule(ctx context.Context, id string) (*domain.SSHRule, error) {
	return t.store.GetSSHRule(ctx, id)
}
func (t *Tx) ListSSHRules(ctx context.Context, stackID string) ([]*domain.SSHRule, error) {
	return t.store.ListSSHRules(ctx, stackID)
}
func (t *Tx) ListAllSSHRules(ctx context.Context) ([]*domain.SSHRule, error) {
	return t.store.ListAllSSHRules(ctx)
}
func (t *Tx) UpdateSSHRule(ctx context.Context, rule *domain.SSHRule) error {
	return t.store.UpdateSSHRule(ctx, rule)
}
func (t *Tx) DeleteSSHRule(ctx context.Context, id string) error {
	return t.store.DeleteSSHRule(ctx, id)
}
func (t *Tx) DeleteAllSSHRulesForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllSSHRulesForStack(ctx, stackID)
}
func (t *Tx) CreateGrant(ctx context.Context, grant *domain.Grant) error {
	return t.store.CreateGrant(ctx, grant)
}
func (t *Tx) GetGrant(ctx context.Context, id string) (*domain.Grant, error) {
	return t.store.GetGrant(ctx, id)
}
func (t *Tx) ListGrants(ctx context.Context, stackID string) ([]*domain.Grant, error) {
	return t.store.ListGrants(ctx, stackID)
}
func (t *Tx) ListAllGrants(ctx context.Context) ([]*domain.Grant, error) {
	return t.store.ListAllGrants(ctx)
}
func (t *Tx) UpdateGrant(ctx context.Context, grant *domain.Grant) error {
	return t.store.UpdateGrant(ctx, grant)
}
func (t *Tx) DeleteGrant(ctx context.Context, id string) error {
	return t.store.DeleteGrant(ctx, id)
}
func (t *Tx) DeleteAllGrantsForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllGrantsForStack(ctx, stackID)
}
func (t *Tx) CreateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error {
	return t.store.CreateAutoApprover(ctx, aa)
}
func (t *Tx) GetAutoApprover(ctx context.Context, id string) (*domain.AutoApprover, error) {
	return t.store.GetAutoApprover(ctx, id)
}
func (t *Tx) ListAutoApprovers(ctx context.Context, stackID string) ([]*domain.AutoApprover, error) {
	return t.store.ListAutoApprovers(ctx, stackID)
}
func (t *Tx) ListAllAutoApprovers(ctx context.Context) ([]*domain.AutoApprover, error) {
	return t.store.ListAllAutoApprovers(ctx)
}
func (t *Tx) UpdateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error {
	return t.store.UpdateAutoApprover(ctx, aa)
}
func (t *Tx) DeleteAutoApprover(ctx context.Context, id string) error {
	return t.store.DeleteAutoApprover(ctx, id)
}
func (t *Tx) DeleteAllAutoApproversForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllAutoApproversForStack(ctx, stackID)
}
func (t *Tx) CreateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error {
	return t.store.CreateNodeAttr(ctx, attr)
}
func (t *Tx) GetNodeAttr(ctx context.Context, id string) (*domain.NodeAttr, error) {
	return t.store.GetNodeAttr(ctx, id)
}
func (t *Tx) ListNodeAttrs(ctx context.Context, stackID string) ([]*domain.NodeAttr, error) {
	return t.store.ListNodeAttrs(ctx, stackID)
}
func (t *Tx) ListAllNodeAttrs(ctx context.Context) ([]*domain.NodeAttr, error) {
	return t.store.ListAllNodeAttrs(ctx)
}
func (t *Tx) UpdateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error {
	return t.store.UpdateNodeAttr(ctx, attr)
}
func (t *Tx) DeleteNodeAttr(ctx context.Context, id string) error {
	return t.store.DeleteNodeAttr(ctx, id)
}
func (t *Tx) DeleteAllNodeAttrsForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllNodeAttrsForStack(ctx, stackID)
}
func (t *Tx) CreatePosture(ctx context.Context, posture *domain.Posture) error {
	return t.store.CreatePosture(ctx, posture)
}
func (t *Tx) GetPosture(ctx context.Context, stackID, name string) (*domain.Posture, error) {
	return t.store.GetPosture(ctx, stackID, name)
}
func (t *Tx) ListPostures(ctx context.Context, stackID string) ([]*domain.Posture, error) {
	return t.store.ListPostures(ctx, stackID)
}
func (t *Tx) ListAllPostures(ctx context.Context) ([]*domain.Posture, error) {
	return t.store.ListAllPostures(ctx)
}
func (t *Tx) UpdatePosture(ctx context.Context, posture *domain.Posture) error {
	return t.store.UpdatePosture(ctx, posture)
}
func (t *Tx) DeletePosture(ctx context.Context, stackID, name string) error {
	return t.store.DeletePosture(ctx, stackID, name)
}
func (t *Tx) GetPostureByID(ctx context.Context, id string) (*domain.Posture, error) {
	return t.store.GetPostureByID(ctx, id)
}
func (t *Tx) DeletePostureByID(ctx context.Context, id string) error {
	return t.store.DeletePostureByID(ctx, id)
}
func (t *Tx) DeleteAllPosturesForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllPosturesForStack(ctx, stackID)
}
func (t *Tx) CreateIPSet(ctx context.Context, ipset *domain.IPSet) error {
	return t.store.CreateIPSet(ctx, ipset)
}
func (t *Tx) GetIPSet(ctx context.Context, stackID, name string) (*domain.IPSet, error) {
	return t.store.GetIPSet(ctx, stackID, name)
}
func (t *Tx) ListIPSets(ctx context.Context, stackID string) ([]*domain.IPSet, error) {
	return t.store.ListIPSets(ctx, stackID)
}
func (t *Tx) ListAllIPSets(ctx context.Context) ([]*domain.IPSet, error) {
	return t.store.ListAllIPSets(ctx)
}
func (t *Tx) UpdateIPSet(ctx context.Context, ipset *domain.IPSet) error {
	return t.store.UpdateIPSet(ctx, ipset)
}
func (t *Tx) DeleteIPSet(ctx context.Context, stackID, name string) error {
	return t.store.DeleteIPSet(ctx, stackID, name)
}
func (t *Tx) GetIPSetByID(ctx context.Context, id string) (*domain.IPSet, error) {
	return t.store.GetIPSetByID(ctx, id)
}
func (t *Tx) DeleteIPSetByID(ctx context.Context, id string) error {
	return t.store.DeleteIPSetByID(ctx, id)
}
func (t *Tx) DeleteAllIPSetsForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllIPSetsForStack(ctx, stackID)
}
func (t *Tx) CreateACLTest(ctx context.Context, test *domain.ACLTest) error {
	return t.store.CreateACLTest(ctx, test)
}
func (t *Tx) GetACLTest(ctx context.Context, id string) (*domain.ACLTest, error) {
	return t.store.GetACLTest(ctx, id)
}
func (t *Tx) ListACLTests(ctx context.Context, stackID string) ([]*domain.ACLTest, error) {
	return t.store.ListACLTests(ctx, stackID)
}
func (t *Tx) ListAllACLTests(ctx context.Context) ([]*domain.ACLTest, error) {
	return t.store.ListAllACLTests(ctx)
}
func (t *Tx) UpdateACLTest(ctx context.Context, test *domain.ACLTest) error {
	return t.store.UpdateACLTest(ctx, test)
}
func (t *Tx) DeleteACLTest(ctx context.Context, id string) error {
	return t.store.DeleteACLTest(ctx, id)
}
func (t *Tx) DeleteAllACLTestsForStack(ctx context.Context, stackID string) error {
	return t.store.DeleteAllACLTestsForStack(ctx, stackID)
}
func (t *Tx) CreatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error {
	return t.store.CreatePolicyVersion(ctx, version)
}
func (t *Tx) GetPolicyVersion(ctx context.Context, id string) (*domain.PolicyVersion, error) {
	return t.store.GetPolicyVersion(ctx, id)
}
func (t *Tx) GetLatestPolicyVersion(ctx context.Context) (*domain.PolicyVersion, error) {
	return t.store.GetLatestPolicyVersion(ctx)
}
func (t *Tx) ListPolicyVersions(ctx context.Context, limit, offset int) ([]*domain.PolicyVersion, error) {
	return t.store.ListPolicyVersions(ctx, limit, offset)
}
func (t *Tx) UpdatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error {
	return t.store.UpdatePolicyVersion(ctx, version)
}

// ============================================
// API Keys
// ============================================

func (s *Store) CreateAPIKey(ctx context.Context, key *domain.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.apiKeys[key.ID]; exists {
		return domain.ErrAlreadyExists
	}
	s.apiKeys[key.ID] = key
	return nil
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range s.apiKeys {
		if key.KeyHash == keyHash {
			return key, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]*domain.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]*domain.APIKey, 0, len(s.apiKeys))
	for _, key := range s.apiKeys {
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.apiKeys[id]; !exists {
		return domain.ErrNotFound
	}
	delete(s.apiKeys, id)
	return nil
}

func (s *Store) UpdateAPIKeyLastUsed(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, exists := s.apiKeys[id]
	if !exists {
		return domain.ErrNotFound
	}
	now := time.Now()
	key.LastUsedAt = &now
	return nil
}

func (s *Store) CountAPIKeys(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.apiKeys), nil
}

// ============================================
// Stacks
// ============================================

func (s *Store) CreateStack(ctx context.Context, stack *domain.Stack) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.stacks[stack.ID]; exists {
		return domain.ErrAlreadyExists
	}
	for _, existing := range s.stacks {
		if existing.Name == stack.Name {
			return domain.ErrAlreadyExists
		}
	}
	s.stacks[stack.ID] = stack
	return nil
}

func (s *Store) GetStack(ctx context.Context, id string) (*domain.Stack, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stack, exists := s.stacks[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return stack, nil
}

func (s *Store) GetStackByName(ctx context.Context, name string) (*domain.Stack, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, stack := range s.stacks {
		if stack.Name == name {
			return stack, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) ListStacks(ctx context.Context) ([]*domain.Stack, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stacks := make([]*domain.Stack, 0, len(s.stacks))
	for _, stack := range s.stacks {
		stacks = append(stacks, stack)
	}
	sort.Slice(stacks, func(i, j int) bool {
		if stacks[i].Priority != stacks[j].Priority {
			return stacks[i].Priority < stacks[j].Priority
		}
		return stacks[i].Name < stacks[j].Name
	})
	return stacks, nil
}

func (s *Store) UpdateStack(ctx context.Context, stack *domain.Stack) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.stacks[stack.ID]; !exists {
		return domain.ErrNotFound
	}
	s.stacks[stack.ID] = stack
	return nil
}

func (s *Store) DeleteStack(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.stacks[id]; !exists {
		return domain.ErrNotFound
	}
	delete(s.stacks, id)
	return nil
}

// ============================================
// Groups
// ============================================

func groupKey(stackID, name string) string { return stackID + ":" + name }

func (s *Store) CreateGroup(ctx context.Context, group *domain.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := groupKey(group.StackID, group.Name)
	if _, exists := s.groups[key]; exists {
		return domain.ErrAlreadyExists
	}
	s.groups[key] = group
	return nil
}

func (s *Store) GetGroup(ctx context.Context, stackID, name string) (*domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, exists := s.groups[groupKey(stackID, name)]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return group, nil
}

func (s *Store) ListGroups(ctx context.Context, stackID string) ([]*domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groups := make([]*domain.Group, 0)
	for _, group := range s.groups {
		if group.StackID == stackID {
			groups = append(groups, group)
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups, nil
}

func (s *Store) ListAllGroups(ctx context.Context) ([]*domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groups := make([]*domain.Group, 0, len(s.groups))
	for _, group := range s.groups {
		groups = append(groups, group)
	}
	// Sort by stack priority then name
	sort.Slice(groups, func(i, j int) bool {
		si, sj := s.stacks[groups[i].StackID], s.stacks[groups[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return groups[i].Name < groups[j].Name
	})
	return groups, nil
}

func (s *Store) UpdateGroup(ctx context.Context, group *domain.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := groupKey(group.StackID, group.Name)
	if _, exists := s.groups[key]; !exists {
		return domain.ErrNotFound
	}
	s.groups[key] = group
	return nil
}

func (s *Store) DeleteGroup(ctx context.Context, stackID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := groupKey(stackID, name)
	if _, exists := s.groups[key]; !exists {
		return domain.ErrNotFound
	}
	delete(s.groups, key)
	return nil
}

func (s *Store) GetGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, group := range s.groups {
		if group.ID == id {
			return group, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) DeleteGroupByID(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, group := range s.groups {
		if group.ID == id {
			delete(s.groups, key)
			return nil
		}
	}
	return domain.ErrNotFound
}

func (s *Store) DeleteAllGroupsForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, group := range s.groups {
		if group.StackID == stackID {
			delete(s.groups, key)
		}
	}
	return nil
}

// ============================================
// Tag Owners
// ============================================

func tagOwnerKey(stackID, tag string) string { return stackID + ":" + tag }

func (s *Store) CreateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tagOwnerKey(tagOwner.StackID, tagOwner.Tag)
	if _, exists := s.tagOwners[key]; exists {
		return domain.ErrAlreadyExists
	}
	s.tagOwners[key] = tagOwner
	return nil
}

func (s *Store) GetTagOwner(ctx context.Context, stackID, tag string) (*domain.TagOwner, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	to, exists := s.tagOwners[tagOwnerKey(stackID, tag)]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return to, nil
}

func (s *Store) ListTagOwners(ctx context.Context, stackID string) ([]*domain.TagOwner, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tagOwners := make([]*domain.TagOwner, 0)
	for _, to := range s.tagOwners {
		if to.StackID == stackID {
			tagOwners = append(tagOwners, to)
		}
	}
	sort.Slice(tagOwners, func(i, j int) bool { return tagOwners[i].Tag < tagOwners[j].Tag })
	return tagOwners, nil
}

func (s *Store) ListAllTagOwners(ctx context.Context) ([]*domain.TagOwner, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tagOwners := make([]*domain.TagOwner, 0, len(s.tagOwners))
	for _, to := range s.tagOwners {
		tagOwners = append(tagOwners, to)
	}
	sort.Slice(tagOwners, func(i, j int) bool {
		si, sj := s.stacks[tagOwners[i].StackID], s.stacks[tagOwners[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return tagOwners[i].Tag < tagOwners[j].Tag
	})
	return tagOwners, nil
}

func (s *Store) UpdateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tagOwnerKey(tagOwner.StackID, tagOwner.Tag)
	if _, exists := s.tagOwners[key]; !exists {
		return domain.ErrNotFound
	}
	s.tagOwners[key] = tagOwner
	return nil
}

func (s *Store) DeleteTagOwner(ctx context.Context, stackID, tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tagOwnerKey(stackID, tag)
	if _, exists := s.tagOwners[key]; !exists {
		return domain.ErrNotFound
	}
	delete(s.tagOwners, key)
	return nil
}

func (s *Store) GetTagOwnerByID(ctx context.Context, id string) (*domain.TagOwner, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, to := range s.tagOwners {
		if to.ID == id {
			return to, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) DeleteTagOwnerByID(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, to := range s.tagOwners {
		if to.ID == id {
			delete(s.tagOwners, key)
			return nil
		}
	}
	return domain.ErrNotFound
}

func (s *Store) DeleteAllTagOwnersForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, to := range s.tagOwners {
		if to.StackID == stackID {
			delete(s.tagOwners, key)
		}
	}
	return nil
}

// ============================================
// Hosts
// ============================================

func hostKey(stackID, name string) string { return stackID + ":" + name }

func (s *Store) CreateHost(ctx context.Context, host *domain.Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hostKey(host.StackID, host.Name)
	if _, exists := s.hosts[key]; exists {
		return domain.ErrAlreadyExists
	}
	s.hosts[key] = host
	return nil
}

func (s *Store) GetHost(ctx context.Context, stackID, name string) (*domain.Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	host, exists := s.hosts[hostKey(stackID, name)]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return host, nil
}

func (s *Store) ListHosts(ctx context.Context, stackID string) ([]*domain.Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := make([]*domain.Host, 0)
	for _, host := range s.hosts {
		if host.StackID == stackID {
			hosts = append(hosts, host)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	return hosts, nil
}

func (s *Store) ListAllHosts(ctx context.Context) ([]*domain.Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := make([]*domain.Host, 0, len(s.hosts))
	for _, host := range s.hosts {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool {
		si, sj := s.stacks[hosts[i].StackID], s.stacks[hosts[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return hosts[i].Name < hosts[j].Name
	})
	return hosts, nil
}

func (s *Store) UpdateHost(ctx context.Context, host *domain.Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hostKey(host.StackID, host.Name)
	if _, exists := s.hosts[key]; !exists {
		return domain.ErrNotFound
	}
	s.hosts[key] = host
	return nil
}

func (s *Store) DeleteHost(ctx context.Context, stackID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hostKey(stackID, name)
	if _, exists := s.hosts[key]; !exists {
		return domain.ErrNotFound
	}
	delete(s.hosts, key)
	return nil
}

func (s *Store) GetHostByID(ctx context.Context, id string) (*domain.Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, host := range s.hosts {
		if host.ID == id {
			return host, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) DeleteHostByID(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, host := range s.hosts {
		if host.ID == id {
			delete(s.hosts, key)
			return nil
		}
	}
	return domain.ErrNotFound
}

func (s *Store) DeleteAllHostsForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, host := range s.hosts {
		if host.StackID == stackID {
			delete(s.hosts, key)
		}
	}
	return nil
}

// ============================================
// ACL Rules
// ============================================

func (s *Store) CreateACLRule(ctx context.Context, rule *domain.ACLRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.aclRules[rule.ID]; exists {
		return domain.ErrAlreadyExists
	}
	s.aclRules[rule.ID] = rule
	return nil
}

func (s *Store) GetACLRule(ctx context.Context, id string) (*domain.ACLRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rule, exists := s.aclRules[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return rule, nil
}

func (s *Store) ListACLRules(ctx context.Context, stackID string) ([]*domain.ACLRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]*domain.ACLRule, 0)
	for _, rule := range s.aclRules {
		if rule.StackID == stackID {
			rules = append(rules, rule)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Order < rules[j].Order })
	return rules, nil
}

func (s *Store) ListAllACLRules(ctx context.Context) ([]*domain.ACLRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]*domain.ACLRule, 0, len(s.aclRules))
	for _, rule := range s.aclRules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		si, sj := s.stacks[rules[i].StackID], s.stacks[rules[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return rules[i].Order < rules[j].Order
	})
	return rules, nil
}

func (s *Store) UpdateACLRule(ctx context.Context, rule *domain.ACLRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.aclRules[rule.ID]; !exists {
		return domain.ErrNotFound
	}
	s.aclRules[rule.ID] = rule
	return nil
}

func (s *Store) DeleteACLRule(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.aclRules[id]; !exists {
		return domain.ErrNotFound
	}
	delete(s.aclRules, id)
	return nil
}

func (s *Store) DeleteAllACLRulesForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rule := range s.aclRules {
		if rule.StackID == stackID {
			delete(s.aclRules, id)
		}
	}
	return nil
}

// ============================================
// SSH Rules
// ============================================

func (s *Store) CreateSSHRule(ctx context.Context, rule *domain.SSHRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sshRules[rule.ID]; exists {
		return domain.ErrAlreadyExists
	}
	s.sshRules[rule.ID] = rule
	return nil
}

func (s *Store) GetSSHRule(ctx context.Context, id string) (*domain.SSHRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rule, exists := s.sshRules[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return rule, nil
}

func (s *Store) ListSSHRules(ctx context.Context, stackID string) ([]*domain.SSHRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]*domain.SSHRule, 0)
	for _, rule := range s.sshRules {
		if rule.StackID == stackID {
			rules = append(rules, rule)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Order < rules[j].Order })
	return rules, nil
}

func (s *Store) ListAllSSHRules(ctx context.Context) ([]*domain.SSHRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]*domain.SSHRule, 0, len(s.sshRules))
	for _, rule := range s.sshRules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		si, sj := s.stacks[rules[i].StackID], s.stacks[rules[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return rules[i].Order < rules[j].Order
	})
	return rules, nil
}

func (s *Store) UpdateSSHRule(ctx context.Context, rule *domain.SSHRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sshRules[rule.ID]; !exists {
		return domain.ErrNotFound
	}
	s.sshRules[rule.ID] = rule
	return nil
}

func (s *Store) DeleteSSHRule(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sshRules[id]; !exists {
		return domain.ErrNotFound
	}
	delete(s.sshRules, id)
	return nil
}

func (s *Store) DeleteAllSSHRulesForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rule := range s.sshRules {
		if rule.StackID == stackID {
			delete(s.sshRules, id)
		}
	}
	return nil
}

// ============================================
// Grants
// ============================================

func (s *Store) CreateGrant(ctx context.Context, grant *domain.Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.grants[grant.ID]; exists {
		return domain.ErrAlreadyExists
	}
	s.grants[grant.ID] = grant
	return nil
}

func (s *Store) GetGrant(ctx context.Context, id string) (*domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grant, exists := s.grants[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return grant, nil
}

func (s *Store) ListGrants(ctx context.Context, stackID string) ([]*domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grants := make([]*domain.Grant, 0)
	for _, grant := range s.grants {
		if grant.StackID == stackID {
			grants = append(grants, grant)
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Order < grants[j].Order })
	return grants, nil
}

func (s *Store) ListAllGrants(ctx context.Context) ([]*domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grants := make([]*domain.Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		grants = append(grants, grant)
	}
	sort.Slice(grants, func(i, j int) bool {
		si, sj := s.stacks[grants[i].StackID], s.stacks[grants[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return grants[i].Order < grants[j].Order
	})
	return grants, nil
}

func (s *Store) UpdateGrant(ctx context.Context, grant *domain.Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.grants[grant.ID]; !exists {
		return domain.ErrNotFound
	}
	s.grants[grant.ID] = grant
	return nil
}

func (s *Store) DeleteGrant(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.grants[id]; !exists {
		return domain.ErrNotFound
	}
	delete(s.grants, id)
	return nil
}

func (s *Store) DeleteAllGrantsForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, grant := range s.grants {
		if grant.StackID == stackID {
			delete(s.grants, id)
		}
	}
	return nil
}

// ============================================
// Auto Approvers
// ============================================

func (s *Store) CreateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.autoApprovers[aa.ID]; exists {
		return domain.ErrAlreadyExists
	}
	s.autoApprovers[aa.ID] = aa
	return nil
}

func (s *Store) GetAutoApprover(ctx context.Context, id string) (*domain.AutoApprover, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	aa, exists := s.autoApprovers[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return aa, nil
}

func (s *Store) ListAutoApprovers(ctx context.Context, stackID string) ([]*domain.AutoApprover, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	aas := make([]*domain.AutoApprover, 0)
	for _, aa := range s.autoApprovers {
		if aa.StackID == stackID {
			aas = append(aas, aa)
		}
	}
	return aas, nil
}

func (s *Store) ListAllAutoApprovers(ctx context.Context) ([]*domain.AutoApprover, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	aas := make([]*domain.AutoApprover, 0, len(s.autoApprovers))
	for _, aa := range s.autoApprovers {
		aas = append(aas, aa)
	}
	sort.Slice(aas, func(i, j int) bool {
		si, sj := s.stacks[aas[i].StackID], s.stacks[aas[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return aas[i].Type < aas[j].Type
	})
	return aas, nil
}

func (s *Store) UpdateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.autoApprovers[aa.ID]; !exists {
		return domain.ErrNotFound
	}
	s.autoApprovers[aa.ID] = aa
	return nil
}

func (s *Store) DeleteAutoApprover(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.autoApprovers[id]; !exists {
		return domain.ErrNotFound
	}
	delete(s.autoApprovers, id)
	return nil
}

func (s *Store) DeleteAllAutoApproversForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, aa := range s.autoApprovers {
		if aa.StackID == stackID {
			delete(s.autoApprovers, id)
		}
	}
	return nil
}

// ============================================
// Node Attributes
// ============================================

func (s *Store) CreateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.nodeAttrs[attr.ID]; exists {
		return domain.ErrAlreadyExists
	}
	s.nodeAttrs[attr.ID] = attr
	return nil
}

func (s *Store) GetNodeAttr(ctx context.Context, id string) (*domain.NodeAttr, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	attr, exists := s.nodeAttrs[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return attr, nil
}

func (s *Store) ListNodeAttrs(ctx context.Context, stackID string) ([]*domain.NodeAttr, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	attrs := make([]*domain.NodeAttr, 0)
	for _, attr := range s.nodeAttrs {
		if attr.StackID == stackID {
			attrs = append(attrs, attr)
		}
	}
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].Order < attrs[j].Order })
	return attrs, nil
}

func (s *Store) ListAllNodeAttrs(ctx context.Context) ([]*domain.NodeAttr, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	attrs := make([]*domain.NodeAttr, 0, len(s.nodeAttrs))
	for _, attr := range s.nodeAttrs {
		attrs = append(attrs, attr)
	}
	sort.Slice(attrs, func(i, j int) bool {
		si, sj := s.stacks[attrs[i].StackID], s.stacks[attrs[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return attrs[i].Order < attrs[j].Order
	})
	return attrs, nil
}

func (s *Store) UpdateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.nodeAttrs[attr.ID]; !exists {
		return domain.ErrNotFound
	}
	s.nodeAttrs[attr.ID] = attr
	return nil
}

func (s *Store) DeleteNodeAttr(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.nodeAttrs[id]; !exists {
		return domain.ErrNotFound
	}
	delete(s.nodeAttrs, id)
	return nil
}

func (s *Store) DeleteAllNodeAttrsForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, attr := range s.nodeAttrs {
		if attr.StackID == stackID {
			delete(s.nodeAttrs, id)
		}
	}
	return nil
}

// ============================================
// Postures
// ============================================

func postureKey(stackID, name string) string { return stackID + ":" + name }

func (s *Store) CreatePosture(ctx context.Context, posture *domain.Posture) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := postureKey(posture.StackID, posture.Name)
	if _, exists := s.postures[key]; exists {
		return domain.ErrAlreadyExists
	}
	s.postures[key] = posture
	return nil
}

func (s *Store) GetPosture(ctx context.Context, stackID, name string) (*domain.Posture, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	posture, exists := s.postures[postureKey(stackID, name)]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return posture, nil
}

func (s *Store) ListPostures(ctx context.Context, stackID string) ([]*domain.Posture, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	postures := make([]*domain.Posture, 0)
	for _, posture := range s.postures {
		if posture.StackID == stackID {
			postures = append(postures, posture)
		}
	}
	sort.Slice(postures, func(i, j int) bool { return postures[i].Name < postures[j].Name })
	return postures, nil
}

func (s *Store) ListAllPostures(ctx context.Context) ([]*domain.Posture, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	postures := make([]*domain.Posture, 0, len(s.postures))
	for _, posture := range s.postures {
		postures = append(postures, posture)
	}
	sort.Slice(postures, func(i, j int) bool {
		si, sj := s.stacks[postures[i].StackID], s.stacks[postures[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return postures[i].Name < postures[j].Name
	})
	return postures, nil
}

func (s *Store) UpdatePosture(ctx context.Context, posture *domain.Posture) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := postureKey(posture.StackID, posture.Name)
	if _, exists := s.postures[key]; !exists {
		return domain.ErrNotFound
	}
	s.postures[key] = posture
	return nil
}

func (s *Store) DeletePosture(ctx context.Context, stackID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := postureKey(stackID, name)
	if _, exists := s.postures[key]; !exists {
		return domain.ErrNotFound
	}
	delete(s.postures, key)
	return nil
}

func (s *Store) GetPostureByID(ctx context.Context, id string) (*domain.Posture, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, posture := range s.postures {
		if posture.ID == id {
			return posture, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) DeletePostureByID(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, posture := range s.postures {
		if posture.ID == id {
			delete(s.postures, key)
			return nil
		}
	}
	return domain.ErrNotFound
}

func (s *Store) DeleteAllPosturesForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, posture := range s.postures {
		if posture.StackID == stackID {
			delete(s.postures, key)
		}
	}
	return nil
}

// ============================================
// IP Sets
// ============================================

func ipsetKey(stackID, name string) string { return stackID + ":" + name }

func (s *Store) CreateIPSet(ctx context.Context, ipset *domain.IPSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ipsetKey(ipset.StackID, ipset.Name)
	if _, exists := s.ipsets[key]; exists {
		return domain.ErrAlreadyExists
	}
	s.ipsets[key] = ipset
	return nil
}

func (s *Store) GetIPSet(ctx context.Context, stackID, name string) (*domain.IPSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ipset, exists := s.ipsets[ipsetKey(stackID, name)]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return ipset, nil
}

func (s *Store) ListIPSets(ctx context.Context, stackID string) ([]*domain.IPSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ipsets := make([]*domain.IPSet, 0)
	for _, ipset := range s.ipsets {
		if ipset.StackID == stackID {
			ipsets = append(ipsets, ipset)
		}
	}
	sort.Slice(ipsets, func(i, j int) bool { return ipsets[i].Name < ipsets[j].Name })
	return ipsets, nil
}

func (s *Store) ListAllIPSets(ctx context.Context) ([]*domain.IPSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ipsets := make([]*domain.IPSet, 0, len(s.ipsets))
	for _, ipset := range s.ipsets {
		ipsets = append(ipsets, ipset)
	}
	sort.Slice(ipsets, func(i, j int) bool {
		si, sj := s.stacks[ipsets[i].StackID], s.stacks[ipsets[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return ipsets[i].Name < ipsets[j].Name
	})
	return ipsets, nil
}

func (s *Store) UpdateIPSet(ctx context.Context, ipset *domain.IPSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ipsetKey(ipset.StackID, ipset.Name)
	if _, exists := s.ipsets[key]; !exists {
		return domain.ErrNotFound
	}
	s.ipsets[key] = ipset
	return nil
}

func (s *Store) DeleteIPSet(ctx context.Context, stackID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ipsetKey(stackID, name)
	if _, exists := s.ipsets[key]; !exists {
		return domain.ErrNotFound
	}
	delete(s.ipsets, key)
	return nil
}

func (s *Store) GetIPSetByID(ctx context.Context, id string) (*domain.IPSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ipset := range s.ipsets {
		if ipset.ID == id {
			return ipset, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) DeleteIPSetByID(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, ipset := range s.ipsets {
		if ipset.ID == id {
			delete(s.ipsets, key)
			return nil
		}
	}
	return domain.ErrNotFound
}

func (s *Store) DeleteAllIPSetsForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, ipset := range s.ipsets {
		if ipset.StackID == stackID {
			delete(s.ipsets, key)
		}
	}
	return nil
}

// ============================================
// ACL Tests
// ============================================

func (s *Store) CreateACLTest(ctx context.Context, test *domain.ACLTest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.aclTests[test.ID]; exists {
		return domain.ErrAlreadyExists
	}
	s.aclTests[test.ID] = test
	return nil
}

func (s *Store) GetACLTest(ctx context.Context, id string) (*domain.ACLTest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	test, exists := s.aclTests[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return test, nil
}

func (s *Store) ListACLTests(ctx context.Context, stackID string) ([]*domain.ACLTest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tests := make([]*domain.ACLTest, 0)
	for _, test := range s.aclTests {
		if test.StackID == stackID {
			tests = append(tests, test)
		}
	}
	sort.Slice(tests, func(i, j int) bool { return tests[i].Order < tests[j].Order })
	return tests, nil
}

func (s *Store) ListAllACLTests(ctx context.Context) ([]*domain.ACLTest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tests := make([]*domain.ACLTest, 0, len(s.aclTests))
	for _, test := range s.aclTests {
		tests = append(tests, test)
	}
	sort.Slice(tests, func(i, j int) bool {
		si, sj := s.stacks[tests[i].StackID], s.stacks[tests[j].StackID]
		if si != nil && sj != nil && si.Priority != sj.Priority {
			return si.Priority < sj.Priority
		}
		return tests[i].Order < tests[j].Order
	})
	return tests, nil
}

func (s *Store) UpdateACLTest(ctx context.Context, test *domain.ACLTest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.aclTests[test.ID]; !exists {
		return domain.ErrNotFound
	}
	s.aclTests[test.ID] = test
	return nil
}

func (s *Store) DeleteACLTest(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.aclTests[id]; !exists {
		return domain.ErrNotFound
	}
	delete(s.aclTests, id)
	return nil
}

func (s *Store) DeleteAllACLTestsForStack(ctx context.Context, stackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, test := range s.aclTests {
		if test.StackID == stackID {
			delete(s.aclTests, id)
		}
	}
	return nil
}

// ============================================
// Policy Versions
// ============================================

func (s *Store) CreatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.policyVersions[version.ID]; exists {
		return domain.ErrAlreadyExists
	}
	s.policyVersions[version.ID] = version
	return nil
}

func (s *Store) GetPolicyVersion(ctx context.Context, id string) (*domain.PolicyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	version, exists := s.policyVersions[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return version, nil
}

func (s *Store) GetLatestPolicyVersion(ctx context.Context) (*domain.PolicyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest *domain.PolicyVersion
	for _, v := range s.policyVersions {
		if latest == nil || v.VersionNumber > latest.VersionNumber {
			latest = v
		}
	}
	if latest == nil {
		return nil, domain.ErrNotFound
	}
	return latest, nil
}

func (s *Store) ListPolicyVersions(ctx context.Context, limit, offset int) ([]*domain.PolicyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := make([]*domain.PolicyVersion, 0, len(s.policyVersions))
	for _, v := range s.policyVersions {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].VersionNumber > versions[j].VersionNumber
	})
	if offset >= len(versions) {
		return []*domain.PolicyVersion{}, nil
	}
	end := offset + limit
	if end > len(versions) {
		end = len(versions)
	}
	return versions[offset:end], nil
}

func (s *Store) UpdatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.policyVersions[version.ID]; !exists {
		return domain.ErrNotFound
	}
	s.policyVersions[version.ID] = version
	return nil
}
