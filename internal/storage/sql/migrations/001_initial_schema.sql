-- +goose Up
-- +goose StatementBegin

-- API Keys table
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);

-- Stacks table
CREATE TABLE stacks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 100,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_stacks_priority ON stacks(priority);

-- Groups table
CREATE TABLE groups (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stack_id, name)
);

CREATE INDEX idx_groups_stack_id ON groups(stack_id);

-- Group members (array stored as separate table)
CREATE TABLE group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    member TEXT NOT NULL,
    PRIMARY KEY (group_id, member)
);

-- Tag owners table
CREATE TABLE tag_owners (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stack_id, tag)
);

CREATE INDEX idx_tag_owners_stack_id ON tag_owners(stack_id);

-- Tag owner entries (array stored as separate table)
CREATE TABLE tag_owner_entries (
    tag_owner_id TEXT NOT NULL REFERENCES tag_owners(id) ON DELETE CASCADE,
    owner TEXT NOT NULL,
    PRIMARY KEY (tag_owner_id, owner)
);

-- Hosts table
CREATE TABLE hosts (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stack_id, name)
);

CREATE INDEX idx_hosts_stack_id ON hosts(stack_id);

-- ACL rules table
CREATE TABLE acl_rules (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    rule_order INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL DEFAULT 'accept',
    protocol TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_acl_rules_stack_id ON acl_rules(stack_id);
CREATE INDEX idx_acl_rules_order ON acl_rules(stack_id, rule_order);

-- ACL rule sources
CREATE TABLE acl_rule_sources (
    rule_id TEXT NOT NULL REFERENCES acl_rules(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, seq)
);

-- ACL rule destinations
CREATE TABLE acl_rule_destinations (
    rule_id TEXT NOT NULL REFERENCES acl_rules(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, seq)
);

-- SSH rules table
CREATE TABLE ssh_rules (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    rule_order INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL,
    check_period TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ssh_rules_stack_id ON ssh_rules(stack_id);
CREATE INDEX idx_ssh_rules_order ON ssh_rules(stack_id, rule_order);

-- SSH rule sources
CREATE TABLE ssh_rule_sources (
    rule_id TEXT NOT NULL REFERENCES ssh_rules(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, seq)
);

-- SSH rule destinations
CREATE TABLE ssh_rule_destinations (
    rule_id TEXT NOT NULL REFERENCES ssh_rules(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, seq)
);

-- SSH rule users
CREATE TABLE ssh_rule_users (
    rule_id TEXT NOT NULL REFERENCES ssh_rules(id) ON DELETE CASCADE,
    user_name TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, seq)
);

-- Grants table
CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    rule_order INTEGER NOT NULL DEFAULT 0,
    app_json TEXT, -- JSON blob for app permissions
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_grants_stack_id ON grants(stack_id);
CREATE INDEX idx_grants_order ON grants(stack_id, rule_order);

-- Grant sources
CREATE TABLE grant_sources (
    grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (grant_id, seq)
);

-- Grant destinations
CREATE TABLE grant_destinations (
    grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (grant_id, seq)
);

-- Grant IPs
CREATE TABLE grant_ips (
    grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (grant_id, seq)
);

-- Auto approvers table
CREATE TABLE auto_approvers (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    type TEXT NOT NULL, -- 'routes' or 'exitNode'
    match TEXT NOT NULL, -- Route CIDR or '*' for exit nodes
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stack_id, type, match)
);

CREATE INDEX idx_auto_approvers_stack_id ON auto_approvers(stack_id);

-- Auto approver entries
CREATE TABLE auto_approver_entries (
    auto_approver_id TEXT NOT NULL REFERENCES auto_approvers(id) ON DELETE CASCADE,
    approver TEXT NOT NULL,
    PRIMARY KEY (auto_approver_id, approver)
);

-- Node attributes table
CREATE TABLE node_attrs (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    rule_order INTEGER NOT NULL DEFAULT 0,
    app_json TEXT, -- JSON blob for app config
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_node_attrs_stack_id ON node_attrs(stack_id);
CREATE INDEX idx_node_attrs_order ON node_attrs(stack_id, rule_order);

-- Node attr targets
CREATE TABLE node_attr_targets (
    node_attr_id TEXT NOT NULL REFERENCES node_attrs(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_attr_id, seq)
);

-- Node attr attributes
CREATE TABLE node_attr_attrs (
    node_attr_id TEXT NOT NULL REFERENCES node_attrs(id) ON DELETE CASCADE,
    attr TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_attr_id, seq)
);

-- Postures table
CREATE TABLE postures (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stack_id, name)
);

CREATE INDEX idx_postures_stack_id ON postures(stack_id);

-- Posture rules
CREATE TABLE posture_rules (
    posture_id TEXT NOT NULL REFERENCES postures(id) ON DELETE CASCADE,
    rule TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (posture_id, seq)
);

-- IP sets table
CREATE TABLE ip_sets (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stack_id, name)
);

CREATE INDEX idx_ip_sets_stack_id ON ip_sets(stack_id);

-- IP set addresses
CREATE TABLE ip_set_addresses (
    ip_set_id TEXT NOT NULL REFERENCES ip_sets(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip_set_id, seq)
);

-- ACL tests table
CREATE TABLE acl_tests (
    id TEXT PRIMARY KEY,
    stack_id TEXT NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    rule_order INTEGER NOT NULL DEFAULT 0,
    src TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_acl_tests_stack_id ON acl_tests(stack_id);
CREATE INDEX idx_acl_tests_order ON acl_tests(stack_id, rule_order);

-- ACL test accept entries
CREATE TABLE acl_test_accepts (
    test_id TEXT NOT NULL REFERENCES acl_tests(id) ON DELETE CASCADE,
    accept TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (test_id, seq)
);

-- ACL test deny entries
CREATE TABLE acl_test_denies (
    test_id TEXT NOT NULL REFERENCES acl_tests(id) ON DELETE CASCADE,
    deny TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (test_id, seq)
);

-- Policy versions table
CREATE TABLE policy_versions (
    id TEXT PRIMARY KEY,
    version_number INTEGER NOT NULL UNIQUE,
    rendered_policy TEXT NOT NULL,
    tailscale_etag TEXT,
    push_status TEXT NOT NULL DEFAULT 'pending',
    push_error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    pushed_at TIMESTAMP
);

CREATE INDEX idx_policy_versions_number ON policy_versions(version_number DESC);
CREATE INDEX idx_policy_versions_status ON policy_versions(push_status);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS acl_test_denies;
DROP TABLE IF EXISTS acl_test_accepts;
DROP TABLE IF EXISTS acl_tests;
DROP TABLE IF EXISTS ip_set_addresses;
DROP TABLE IF EXISTS ip_sets;
DROP TABLE IF EXISTS posture_rules;
DROP TABLE IF EXISTS postures;
DROP TABLE IF EXISTS node_attr_attrs;
DROP TABLE IF EXISTS node_attr_targets;
DROP TABLE IF EXISTS node_attrs;
DROP TABLE IF EXISTS auto_approver_entries;
DROP TABLE IF EXISTS auto_approvers;
DROP TABLE IF EXISTS grant_ips;
DROP TABLE IF EXISTS grant_destinations;
DROP TABLE IF EXISTS grant_sources;
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS ssh_rule_users;
DROP TABLE IF EXISTS ssh_rule_destinations;
DROP TABLE IF EXISTS ssh_rule_sources;
DROP TABLE IF EXISTS ssh_rules;
DROP TABLE IF EXISTS acl_rule_destinations;
DROP TABLE IF EXISTS acl_rule_sources;
DROP TABLE IF EXISTS acl_rules;
DROP TABLE IF EXISTS hosts;
DROP TABLE IF EXISTS tag_owner_entries;
DROP TABLE IF EXISTS tag_owners;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS stacks;
DROP TABLE IF EXISTS policy_versions;
DROP TABLE IF EXISTS api_keys;

-- +goose StatementEnd
