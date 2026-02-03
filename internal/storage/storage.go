package storage

import (
	"context"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// Storage defines the interface for the storage layer.
// Implementations must be safe for concurrent use.
type Storage interface {
	// Close closes the storage connection.
	Close() error

	// API Keys
	CreateAPIKey(ctx context.Context, key *domain.APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error)
	ListAPIKeys(ctx context.Context) ([]*domain.APIKey, error)
	DeleteAPIKey(ctx context.Context, id string) error
	UpdateAPIKeyLastUsed(ctx context.Context, id string) error
	CountAPIKeys(ctx context.Context) (int, error)

	// Stacks
	CreateStack(ctx context.Context, stack *domain.Stack) error
	GetStack(ctx context.Context, id string) (*domain.Stack, error)
	GetStackByName(ctx context.Context, name string) (*domain.Stack, error)
	ListStacks(ctx context.Context) ([]*domain.Stack, error)
	UpdateStack(ctx context.Context, stack *domain.Stack) error
	DeleteStack(ctx context.Context, id string) error

	// Groups
	CreateGroup(ctx context.Context, group *domain.Group) error
	GetGroup(ctx context.Context, stackID, name string) (*domain.Group, error)
	ListGroups(ctx context.Context, stackID string) ([]*domain.Group, error)
	ListAllGroups(ctx context.Context) ([]*domain.Group, error)
	UpdateGroup(ctx context.Context, group *domain.Group) error
	DeleteGroup(ctx context.Context, stackID, name string) error
	DeleteAllGroupsForStack(ctx context.Context, stackID string) error

	// Tag Owners
	CreateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error
	GetTagOwner(ctx context.Context, stackID, tag string) (*domain.TagOwner, error)
	ListTagOwners(ctx context.Context, stackID string) ([]*domain.TagOwner, error)
	ListAllTagOwners(ctx context.Context) ([]*domain.TagOwner, error)
	UpdateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error
	DeleteTagOwner(ctx context.Context, stackID, tag string) error
	DeleteAllTagOwnersForStack(ctx context.Context, stackID string) error

	// Hosts
	CreateHost(ctx context.Context, host *domain.Host) error
	GetHost(ctx context.Context, stackID, name string) (*domain.Host, error)
	ListHosts(ctx context.Context, stackID string) ([]*domain.Host, error)
	ListAllHosts(ctx context.Context) ([]*domain.Host, error)
	UpdateHost(ctx context.Context, host *domain.Host) error
	DeleteHost(ctx context.Context, stackID, name string) error
	DeleteAllHostsForStack(ctx context.Context, stackID string) error

	// ACL Rules
	CreateACLRule(ctx context.Context, rule *domain.ACLRule) error
	GetACLRule(ctx context.Context, id string) (*domain.ACLRule, error)
	ListACLRules(ctx context.Context, stackID string) ([]*domain.ACLRule, error)
	ListAllACLRules(ctx context.Context) ([]*domain.ACLRule, error)
	UpdateACLRule(ctx context.Context, rule *domain.ACLRule) error
	DeleteACLRule(ctx context.Context, id string) error
	DeleteAllACLRulesForStack(ctx context.Context, stackID string) error

	// SSH Rules
	CreateSSHRule(ctx context.Context, rule *domain.SSHRule) error
	GetSSHRule(ctx context.Context, id string) (*domain.SSHRule, error)
	ListSSHRules(ctx context.Context, stackID string) ([]*domain.SSHRule, error)
	ListAllSSHRules(ctx context.Context) ([]*domain.SSHRule, error)
	UpdateSSHRule(ctx context.Context, rule *domain.SSHRule) error
	DeleteSSHRule(ctx context.Context, id string) error
	DeleteAllSSHRulesForStack(ctx context.Context, stackID string) error

	// Grants
	CreateGrant(ctx context.Context, grant *domain.Grant) error
	GetGrant(ctx context.Context, id string) (*domain.Grant, error)
	ListGrants(ctx context.Context, stackID string) ([]*domain.Grant, error)
	ListAllGrants(ctx context.Context) ([]*domain.Grant, error)
	UpdateGrant(ctx context.Context, grant *domain.Grant) error
	DeleteGrant(ctx context.Context, id string) error
	DeleteAllGrantsForStack(ctx context.Context, stackID string) error

	// Auto Approvers
	CreateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error
	GetAutoApprover(ctx context.Context, id string) (*domain.AutoApprover, error)
	ListAutoApprovers(ctx context.Context, stackID string) ([]*domain.AutoApprover, error)
	ListAllAutoApprovers(ctx context.Context) ([]*domain.AutoApprover, error)
	UpdateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error
	DeleteAutoApprover(ctx context.Context, id string) error
	DeleteAllAutoApproversForStack(ctx context.Context, stackID string) error

	// Node Attributes
	CreateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error
	GetNodeAttr(ctx context.Context, id string) (*domain.NodeAttr, error)
	ListNodeAttrs(ctx context.Context, stackID string) ([]*domain.NodeAttr, error)
	ListAllNodeAttrs(ctx context.Context) ([]*domain.NodeAttr, error)
	UpdateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error
	DeleteNodeAttr(ctx context.Context, id string) error
	DeleteAllNodeAttrsForStack(ctx context.Context, stackID string) error

	// Postures
	CreatePosture(ctx context.Context, posture *domain.Posture) error
	GetPosture(ctx context.Context, stackID, name string) (*domain.Posture, error)
	ListPostures(ctx context.Context, stackID string) ([]*domain.Posture, error)
	ListAllPostures(ctx context.Context) ([]*domain.Posture, error)
	UpdatePosture(ctx context.Context, posture *domain.Posture) error
	DeletePosture(ctx context.Context, stackID, name string) error
	DeleteAllPosturesForStack(ctx context.Context, stackID string) error

	// IP Sets
	CreateIPSet(ctx context.Context, ipset *domain.IPSet) error
	GetIPSet(ctx context.Context, stackID, name string) (*domain.IPSet, error)
	ListIPSets(ctx context.Context, stackID string) ([]*domain.IPSet, error)
	ListAllIPSets(ctx context.Context) ([]*domain.IPSet, error)
	UpdateIPSet(ctx context.Context, ipset *domain.IPSet) error
	DeleteIPSet(ctx context.Context, stackID, name string) error
	DeleteAllIPSetsForStack(ctx context.Context, stackID string) error

	// ACL Tests
	CreateACLTest(ctx context.Context, test *domain.ACLTest) error
	GetACLTest(ctx context.Context, id string) (*domain.ACLTest, error)
	ListACLTests(ctx context.Context, stackID string) ([]*domain.ACLTest, error)
	ListAllACLTests(ctx context.Context) ([]*domain.ACLTest, error)
	UpdateACLTest(ctx context.Context, test *domain.ACLTest) error
	DeleteACLTest(ctx context.Context, id string) error
	DeleteAllACLTestsForStack(ctx context.Context, stackID string) error

	// Policy Versions
	CreatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error
	GetPolicyVersion(ctx context.Context, id string) (*domain.PolicyVersion, error)
	GetLatestPolicyVersion(ctx context.Context) (*domain.PolicyVersion, error)
	ListPolicyVersions(ctx context.Context, limit, offset int) ([]*domain.PolicyVersion, error)
	UpdatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error

	// Transaction support
	BeginTx(ctx context.Context) (Transaction, error)
}

// Transaction represents a database transaction.
type Transaction interface {
	Storage
	Commit() error
	Rollback() error
}
