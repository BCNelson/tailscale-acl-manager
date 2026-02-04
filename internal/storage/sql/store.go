package sql

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// isUniqueViolation checks if an error is a UNIQUE constraint violation.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// SQLite
	if strings.Contains(errStr, "UNIQUE constraint failed") {
		return true
	}
	// PostgreSQL
	if strings.Contains(errStr, "duplicate key value violates unique constraint") {
		return true
	}
	return false
}

// wrapUniqueError converts UNIQUE violations to domain.ErrAlreadyExists.
func wrapUniqueError(err error) error {
	if isUniqueViolation(err) {
		return domain.ErrAlreadyExists
	}
	return err
}

// Store implements the storage.Storage interface using SQL.
type Store struct {
	db     *sqlx.DB
	driver string
}

// New creates a new SQL store.
func New(driver, dsn string) (*Store, error) {
	db, err := sqlx.Connect(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	// Run migrations
	goose.SetBaseFS(embedMigrations)
	if err := goose.SetDialect(driver); err != nil {
		return nil, fmt.Errorf("setting goose dialect: %w", err)
	}

	if err := goose.Up(db.DB, "migrations"); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &Store{db: db, driver: driver}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// BeginTx starts a new transaction.
func (s *Store) BeginTx(ctx context.Context) (storage.Transaction, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &Tx{tx: tx, driver: s.driver}, nil
}

// Tx wraps a database transaction.
type Tx struct {
	tx     *sqlx.Tx
	driver string
}

// Commit commits the transaction.
func (t *Tx) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction.
func (t *Tx) Rollback() error {
	return t.tx.Rollback()
}

// Close is a no-op for transactions (they should be committed or rolled back).
func (t *Tx) Close() error {
	return nil
}

// BeginTx is not supported within a transaction.
func (t *Tx) BeginTx(ctx context.Context) (storage.Transaction, error) {
	return nil, fmt.Errorf("nested transactions not supported")
}

// helper to get the correct database interface
type dbInterface interface {
	sqlx.ExtContext
	SelectContext(ctx context.Context, dest any, query string, args ...any) error
	GetContext(ctx context.Context, dest any, query string, args ...any) error
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// ============================================
// API Keys
// ============================================

func createAPIKey(ctx context.Context, db dbInterface, key *domain.APIKey) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO api_keys (id, name, key_hash, key_prefix, created_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		key.ID, key.Name, key.KeyHash, key.KeyPrefix, key.CreatedAt, key.LastUsedAt)
	return err
}

func (s *Store) CreateAPIKey(ctx context.Context, key *domain.APIKey) error {
	return createAPIKey(ctx, s.db, key)
}

func (t *Tx) CreateAPIKey(ctx context.Context, key *domain.APIKey) error {
	return createAPIKey(ctx, t.tx, key)
}

func getAPIKeyByHash(ctx context.Context, db dbInterface, keyHash string) (*domain.APIKey, error) {
	var key domain.APIKey
	err := db.GetContext(ctx, &key,
		`SELECT id, name, key_hash, key_prefix, created_at, last_used_at FROM api_keys WHERE key_hash = $1`, keyHash)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return &key, err
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	return getAPIKeyByHash(ctx, s.db, keyHash)
}

func (t *Tx) GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	return getAPIKeyByHash(ctx, t.tx, keyHash)
}

func listAPIKeys(ctx context.Context, db dbInterface) ([]*domain.APIKey, error) {
	var keys []*domain.APIKey
	err := db.SelectContext(ctx, &keys,
		`SELECT id, name, key_hash, key_prefix, created_at, last_used_at FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]*domain.APIKey, error) {
	return listAPIKeys(ctx, s.db)
}

func (t *Tx) ListAPIKeys(ctx context.Context) ([]*domain.APIKey, error) {
	return listAPIKeys(ctx, t.tx)
}

func deleteAPIKey(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	return deleteAPIKey(ctx, s.db, id)
}

func (t *Tx) DeleteAPIKey(ctx context.Context, id string) error {
	return deleteAPIKey(ctx, t.tx, id)
}

func updateAPIKeyLastUsed(ctx context.Context, db dbInterface, id string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE api_keys SET last_used_at = $1 WHERE id = $2`, time.Now(), id)
	return err
}

func (s *Store) UpdateAPIKeyLastUsed(ctx context.Context, id string) error {
	return updateAPIKeyLastUsed(ctx, s.db, id)
}

func (t *Tx) UpdateAPIKeyLastUsed(ctx context.Context, id string) error {
	return updateAPIKeyLastUsed(ctx, t.tx, id)
}

func countAPIKeys(ctx context.Context, db dbInterface) (int, error) {
	var count int
	err := db.GetContext(ctx, &count, `SELECT COUNT(*) FROM api_keys`)
	return count, err
}

func (s *Store) CountAPIKeys(ctx context.Context) (int, error) {
	return countAPIKeys(ctx, s.db)
}

func (t *Tx) CountAPIKeys(ctx context.Context) (int, error) {
	return countAPIKeys(ctx, t.tx)
}

// ============================================
// Stacks
// ============================================

func createStack(ctx context.Context, db dbInterface, stack *domain.Stack) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO stacks (id, name, description, priority, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		stack.ID, stack.Name, stack.Description, stack.Priority, stack.CreatedAt, stack.UpdatedAt)
	return wrapUniqueError(err)
}

func (s *Store) CreateStack(ctx context.Context, stack *domain.Stack) error {
	return createStack(ctx, s.db, stack)
}

func (t *Tx) CreateStack(ctx context.Context, stack *domain.Stack) error {
	return createStack(ctx, t.tx, stack)
}

func getStack(ctx context.Context, db dbInterface, id string) (*domain.Stack, error) {
	var stack domain.Stack
	err := db.GetContext(ctx, &stack,
		`SELECT id, name, description, priority, created_at, updated_at FROM stacks WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return &stack, err
}

func (s *Store) GetStack(ctx context.Context, id string) (*domain.Stack, error) {
	return getStack(ctx, s.db, id)
}

func (t *Tx) GetStack(ctx context.Context, id string) (*domain.Stack, error) {
	return getStack(ctx, t.tx, id)
}

func getStackByName(ctx context.Context, db dbInterface, name string) (*domain.Stack, error) {
	var stack domain.Stack
	err := db.GetContext(ctx, &stack,
		`SELECT id, name, description, priority, created_at, updated_at FROM stacks WHERE name = $1`, name)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return &stack, err
}

func (s *Store) GetStackByName(ctx context.Context, name string) (*domain.Stack, error) {
	return getStackByName(ctx, s.db, name)
}

func (t *Tx) GetStackByName(ctx context.Context, name string) (*domain.Stack, error) {
	return getStackByName(ctx, t.tx, name)
}

func listStacks(ctx context.Context, db dbInterface) ([]*domain.Stack, error) {
	var stacks []*domain.Stack
	err := db.SelectContext(ctx, &stacks,
		`SELECT id, name, description, priority, created_at, updated_at FROM stacks ORDER BY priority, name`)
	if err != nil {
		return nil, err
	}
	return stacks, nil
}

func (s *Store) ListStacks(ctx context.Context) ([]*domain.Stack, error) {
	return listStacks(ctx, s.db)
}

func (t *Tx) ListStacks(ctx context.Context) ([]*domain.Stack, error) {
	return listStacks(ctx, t.tx)
}

func updateStack(ctx context.Context, db dbInterface, stack *domain.Stack) error {
	stack.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE stacks SET name = $1, description = $2, priority = $3, updated_at = $4 WHERE id = $5`,
		stack.Name, stack.Description, stack.Priority, stack.UpdatedAt, stack.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateStack(ctx context.Context, stack *domain.Stack) error {
	return updateStack(ctx, s.db, stack)
}

func (t *Tx) UpdateStack(ctx context.Context, stack *domain.Stack) error {
	return updateStack(ctx, t.tx, stack)
}

func deleteStack(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM stacks WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteStack(ctx context.Context, id string) error {
	return deleteStack(ctx, s.db, id)
}

func (t *Tx) DeleteStack(ctx context.Context, id string) error {
	return deleteStack(ctx, t.tx, id)
}

// ============================================
// Groups
// ============================================

func createGroup(ctx context.Context, db dbInterface, group *domain.Group) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO groups (id, stack_id, name, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		group.ID, group.StackID, group.Name, group.CreatedAt, group.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	return insertGroupMembers(ctx, db, group.ID, group.Members)
}

func (s *Store) CreateGroup(ctx context.Context, group *domain.Group) error {
	return createGroup(ctx, s.db, group)
}

func (t *Tx) CreateGroup(ctx context.Context, group *domain.Group) error {
	return createGroup(ctx, t.tx, group)
}

func insertGroupMembers(ctx context.Context, db dbInterface, groupID string, members []string) error {
	for _, member := range members {
		_, err := db.ExecContext(ctx,
			`INSERT INTO group_members (group_id, member) VALUES ($1, $2)`, groupID, member)
		if err != nil {
			return err
		}
	}
	return nil
}

func getGroupMembers(ctx context.Context, db dbInterface, groupID string) ([]string, error) {
	var members []string
	err := db.SelectContext(ctx, &members,
		`SELECT member FROM group_members WHERE group_id = $1`, groupID)
	return members, err
}

func getGroup(ctx context.Context, db dbInterface, stackID, name string) (*domain.Group, error) {
	var group domain.Group
	err := db.GetContext(ctx, &group,
		`SELECT id, stack_id, name, created_at, updated_at FROM groups WHERE stack_id = $1 AND name = $2`, stackID, name)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	group.Members, err = getGroupMembers(ctx, db, group.ID)
	return &group, err
}

func (s *Store) GetGroup(ctx context.Context, stackID, name string) (*domain.Group, error) {
	return getGroup(ctx, s.db, stackID, name)
}

func (t *Tx) GetGroup(ctx context.Context, stackID, name string) (*domain.Group, error) {
	return getGroup(ctx, t.tx, stackID, name)
}

func listGroups(ctx context.Context, db dbInterface, stackID string) ([]*domain.Group, error) {
	var groups []*domain.Group
	err := db.SelectContext(ctx, &groups,
		`SELECT id, stack_id, name, created_at, updated_at FROM groups WHERE stack_id = $1 ORDER BY name`, stackID)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		g.Members, _ = getGroupMembers(ctx, db, g.ID)
	}
	return groups, nil
}

func (s *Store) ListGroups(ctx context.Context, stackID string) ([]*domain.Group, error) {
	return listGroups(ctx, s.db, stackID)
}

func (t *Tx) ListGroups(ctx context.Context, stackID string) ([]*domain.Group, error) {
	return listGroups(ctx, t.tx, stackID)
}

func listAllGroups(ctx context.Context, db dbInterface) ([]*domain.Group, error) {
	var groups []*domain.Group
	err := db.SelectContext(ctx, &groups,
		`SELECT g.id, g.stack_id, g.name, g.created_at, g.updated_at
		 FROM groups g JOIN stacks s ON g.stack_id = s.id
		 ORDER BY s.priority, g.name`)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		g.Members, _ = getGroupMembers(ctx, db, g.ID)
	}
	return groups, nil
}

func (s *Store) ListAllGroups(ctx context.Context) ([]*domain.Group, error) {
	return listAllGroups(ctx, s.db)
}

func (t *Tx) ListAllGroups(ctx context.Context) ([]*domain.Group, error) {
	return listAllGroups(ctx, t.tx)
}

func updateGroup(ctx context.Context, db dbInterface, group *domain.Group) error {
	group.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE groups SET updated_at = $1 WHERE id = $2`, group.UpdatedAt, group.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	// Delete and re-insert members
	_, _ = db.ExecContext(ctx, `DELETE FROM group_members WHERE group_id = $1`, group.ID)
	return insertGroupMembers(ctx, db, group.ID, group.Members)
}

func (s *Store) UpdateGroup(ctx context.Context, group *domain.Group) error {
	return updateGroup(ctx, s.db, group)
}

func (t *Tx) UpdateGroup(ctx context.Context, group *domain.Group) error {
	return updateGroup(ctx, t.tx, group)
}

func deleteGroup(ctx context.Context, db dbInterface, stackID, name string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM groups WHERE stack_id = $1 AND name = $2`, stackID, name)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteGroup(ctx context.Context, stackID, name string) error {
	return deleteGroup(ctx, s.db, stackID, name)
}

func (t *Tx) DeleteGroup(ctx context.Context, stackID, name string) error {
	return deleteGroup(ctx, t.tx, stackID, name)
}

func getGroupByID(ctx context.Context, db dbInterface, id string) (*domain.Group, error) {
	var group domain.Group
	err := db.GetContext(ctx, &group,
		`SELECT id, stack_id, name, created_at, updated_at FROM groups WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	group.Members, err = getGroupMembers(ctx, db, group.ID)
	return &group, err
}

func (s *Store) GetGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	return getGroupByID(ctx, s.db, id)
}

func (t *Tx) GetGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	return getGroupByID(ctx, t.tx, id)
}

func deleteGroupByID(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM groups WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteGroupByID(ctx context.Context, id string) error {
	return deleteGroupByID(ctx, s.db, id)
}

func (t *Tx) DeleteGroupByID(ctx context.Context, id string) error {
	return deleteGroupByID(ctx, t.tx, id)
}

func deleteAllGroupsForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM groups WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllGroupsForStack(ctx context.Context, stackID string) error {
	return deleteAllGroupsForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllGroupsForStack(ctx context.Context, stackID string) error {
	return deleteAllGroupsForStack(ctx, t.tx, stackID)
}

// ============================================
// Tag Owners
// ============================================

func createTagOwner(ctx context.Context, db dbInterface, tagOwner *domain.TagOwner) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO tag_owners (id, stack_id, tag, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		tagOwner.ID, tagOwner.StackID, tagOwner.Tag, tagOwner.CreatedAt, tagOwner.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	return insertTagOwnerEntries(ctx, db, tagOwner.ID, tagOwner.Owners)
}

func (s *Store) CreateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error {
	return createTagOwner(ctx, s.db, tagOwner)
}

func (t *Tx) CreateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error {
	return createTagOwner(ctx, t.tx, tagOwner)
}

func insertTagOwnerEntries(ctx context.Context, db dbInterface, tagOwnerID string, owners []string) error {
	for _, owner := range owners {
		_, err := db.ExecContext(ctx,
			`INSERT INTO tag_owner_entries (tag_owner_id, owner) VALUES ($1, $2)`, tagOwnerID, owner)
		if err != nil {
			return err
		}
	}
	return nil
}

func getTagOwnerEntries(ctx context.Context, db dbInterface, tagOwnerID string) ([]string, error) {
	var owners []string
	err := db.SelectContext(ctx, &owners,
		`SELECT owner FROM tag_owner_entries WHERE tag_owner_id = $1`, tagOwnerID)
	return owners, err
}

func getTagOwner(ctx context.Context, db dbInterface, stackID, tag string) (*domain.TagOwner, error) {
	var tagOwner domain.TagOwner
	err := db.GetContext(ctx, &tagOwner,
		`SELECT id, stack_id, tag, created_at, updated_at FROM tag_owners WHERE stack_id = $1 AND tag = $2`, stackID, tag)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	tagOwner.Owners, err = getTagOwnerEntries(ctx, db, tagOwner.ID)
	return &tagOwner, err
}

func (s *Store) GetTagOwner(ctx context.Context, stackID, tag string) (*domain.TagOwner, error) {
	return getTagOwner(ctx, s.db, stackID, tag)
}

func (t *Tx) GetTagOwner(ctx context.Context, stackID, tag string) (*domain.TagOwner, error) {
	return getTagOwner(ctx, t.tx, stackID, tag)
}

func listTagOwners(ctx context.Context, db dbInterface, stackID string) ([]*domain.TagOwner, error) {
	var tagOwners []*domain.TagOwner
	err := db.SelectContext(ctx, &tagOwners,
		`SELECT id, stack_id, tag, created_at, updated_at FROM tag_owners WHERE stack_id = $1 ORDER BY tag`, stackID)
	if err != nil {
		return nil, err
	}
	for _, to := range tagOwners {
		to.Owners, _ = getTagOwnerEntries(ctx, db, to.ID)
	}
	return tagOwners, nil
}

func (s *Store) ListTagOwners(ctx context.Context, stackID string) ([]*domain.TagOwner, error) {
	return listTagOwners(ctx, s.db, stackID)
}

func (t *Tx) ListTagOwners(ctx context.Context, stackID string) ([]*domain.TagOwner, error) {
	return listTagOwners(ctx, t.tx, stackID)
}

func listAllTagOwners(ctx context.Context, db dbInterface) ([]*domain.TagOwner, error) {
	var tagOwners []*domain.TagOwner
	err := db.SelectContext(ctx, &tagOwners,
		`SELECT t.id, t.stack_id, t.tag, t.created_at, t.updated_at
		 FROM tag_owners t JOIN stacks s ON t.stack_id = s.id
		 ORDER BY s.priority, t.tag`)
	if err != nil {
		return nil, err
	}
	for _, to := range tagOwners {
		to.Owners, _ = getTagOwnerEntries(ctx, db, to.ID)
	}
	return tagOwners, nil
}

func (s *Store) ListAllTagOwners(ctx context.Context) ([]*domain.TagOwner, error) {
	return listAllTagOwners(ctx, s.db)
}

func (t *Tx) ListAllTagOwners(ctx context.Context) ([]*domain.TagOwner, error) {
	return listAllTagOwners(ctx, t.tx)
}

func updateTagOwner(ctx context.Context, db dbInterface, tagOwner *domain.TagOwner) error {
	tagOwner.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE tag_owners SET updated_at = $1 WHERE id = $2`, tagOwner.UpdatedAt, tagOwner.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM tag_owner_entries WHERE tag_owner_id = $1`, tagOwner.ID)
	return insertTagOwnerEntries(ctx, db, tagOwner.ID, tagOwner.Owners)
}

func (s *Store) UpdateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error {
	return updateTagOwner(ctx, s.db, tagOwner)
}

func (t *Tx) UpdateTagOwner(ctx context.Context, tagOwner *domain.TagOwner) error {
	return updateTagOwner(ctx, t.tx, tagOwner)
}

func deleteTagOwner(ctx context.Context, db dbInterface, stackID, tag string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM tag_owners WHERE stack_id = $1 AND tag = $2`, stackID, tag)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteTagOwner(ctx context.Context, stackID, tag string) error {
	return deleteTagOwner(ctx, s.db, stackID, tag)
}

func (t *Tx) DeleteTagOwner(ctx context.Context, stackID, tag string) error {
	return deleteTagOwner(ctx, t.tx, stackID, tag)
}

func getTagOwnerByID(ctx context.Context, db dbInterface, id string) (*domain.TagOwner, error) {
	var tagOwner domain.TagOwner
	err := db.GetContext(ctx, &tagOwner,
		`SELECT id, stack_id, tag, created_at, updated_at FROM tag_owners WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	tagOwner.Owners, err = getTagOwnerEntries(ctx, db, tagOwner.ID)
	return &tagOwner, err
}

func (s *Store) GetTagOwnerByID(ctx context.Context, id string) (*domain.TagOwner, error) {
	return getTagOwnerByID(ctx, s.db, id)
}

func (t *Tx) GetTagOwnerByID(ctx context.Context, id string) (*domain.TagOwner, error) {
	return getTagOwnerByID(ctx, t.tx, id)
}

func deleteTagOwnerByID(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM tag_owners WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteTagOwnerByID(ctx context.Context, id string) error {
	return deleteTagOwnerByID(ctx, s.db, id)
}

func (t *Tx) DeleteTagOwnerByID(ctx context.Context, id string) error {
	return deleteTagOwnerByID(ctx, t.tx, id)
}

func deleteAllTagOwnersForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM tag_owners WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllTagOwnersForStack(ctx context.Context, stackID string) error {
	return deleteAllTagOwnersForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllTagOwnersForStack(ctx context.Context, stackID string) error {
	return deleteAllTagOwnersForStack(ctx, t.tx, stackID)
}

// ============================================
// Hosts
// ============================================

func createHost(ctx context.Context, db dbInterface, host *domain.Host) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO hosts (id, stack_id, name, address, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		host.ID, host.StackID, host.Name, host.Address, host.CreatedAt, host.UpdatedAt)
	return wrapUniqueError(err)
}

func (s *Store) CreateHost(ctx context.Context, host *domain.Host) error {
	return createHost(ctx, s.db, host)
}

func (t *Tx) CreateHost(ctx context.Context, host *domain.Host) error {
	return createHost(ctx, t.tx, host)
}

func getHost(ctx context.Context, db dbInterface, stackID, name string) (*domain.Host, error) {
	var host domain.Host
	err := db.GetContext(ctx, &host,
		`SELECT id, stack_id, name, address, created_at, updated_at FROM hosts WHERE stack_id = $1 AND name = $2`, stackID, name)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return &host, err
}

func (s *Store) GetHost(ctx context.Context, stackID, name string) (*domain.Host, error) {
	return getHost(ctx, s.db, stackID, name)
}

func (t *Tx) GetHost(ctx context.Context, stackID, name string) (*domain.Host, error) {
	return getHost(ctx, t.tx, stackID, name)
}

func listHosts(ctx context.Context, db dbInterface, stackID string) ([]*domain.Host, error) {
	var hosts []*domain.Host
	err := db.SelectContext(ctx, &hosts,
		`SELECT id, stack_id, name, address, created_at, updated_at FROM hosts WHERE stack_id = $1 ORDER BY name`, stackID)
	return hosts, err
}

func (s *Store) ListHosts(ctx context.Context, stackID string) ([]*domain.Host, error) {
	return listHosts(ctx, s.db, stackID)
}

func (t *Tx) ListHosts(ctx context.Context, stackID string) ([]*domain.Host, error) {
	return listHosts(ctx, t.tx, stackID)
}

func listAllHosts(ctx context.Context, db dbInterface) ([]*domain.Host, error) {
	var hosts []*domain.Host
	err := db.SelectContext(ctx, &hosts,
		`SELECT h.id, h.stack_id, h.name, h.address, h.created_at, h.updated_at
		 FROM hosts h JOIN stacks s ON h.stack_id = s.id
		 ORDER BY s.priority, h.name`)
	return hosts, err
}

func (s *Store) ListAllHosts(ctx context.Context) ([]*domain.Host, error) {
	return listAllHosts(ctx, s.db)
}

func (t *Tx) ListAllHosts(ctx context.Context) ([]*domain.Host, error) {
	return listAllHosts(ctx, t.tx)
}

func updateHost(ctx context.Context, db dbInterface, host *domain.Host) error {
	host.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE hosts SET address = $1, updated_at = $2 WHERE id = $3`,
		host.Address, host.UpdatedAt, host.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateHost(ctx context.Context, host *domain.Host) error {
	return updateHost(ctx, s.db, host)
}

func (t *Tx) UpdateHost(ctx context.Context, host *domain.Host) error {
	return updateHost(ctx, t.tx, host)
}

func deleteHost(ctx context.Context, db dbInterface, stackID, name string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM hosts WHERE stack_id = $1 AND name = $2`, stackID, name)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteHost(ctx context.Context, stackID, name string) error {
	return deleteHost(ctx, s.db, stackID, name)
}

func (t *Tx) DeleteHost(ctx context.Context, stackID, name string) error {
	return deleteHost(ctx, t.tx, stackID, name)
}

func getHostByID(ctx context.Context, db dbInterface, id string) (*domain.Host, error) {
	var host domain.Host
	err := db.GetContext(ctx, &host,
		`SELECT id, stack_id, name, address, created_at, updated_at FROM hosts WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return &host, err
}

func (s *Store) GetHostByID(ctx context.Context, id string) (*domain.Host, error) {
	return getHostByID(ctx, s.db, id)
}

func (t *Tx) GetHostByID(ctx context.Context, id string) (*domain.Host, error) {
	return getHostByID(ctx, t.tx, id)
}

func deleteHostByID(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM hosts WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteHostByID(ctx context.Context, id string) error {
	return deleteHostByID(ctx, s.db, id)
}

func (t *Tx) DeleteHostByID(ctx context.Context, id string) error {
	return deleteHostByID(ctx, t.tx, id)
}

func deleteAllHostsForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM hosts WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllHostsForStack(ctx context.Context, stackID string) error {
	return deleteAllHostsForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllHostsForStack(ctx context.Context, stackID string) error {
	return deleteAllHostsForStack(ctx, t.tx, stackID)
}

// ============================================
// ACL Rules
// ============================================

func createACLRule(ctx context.Context, db dbInterface, rule *domain.ACLRule) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO acl_rules (id, stack_id, rule_order, action, protocol, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		rule.ID, rule.StackID, rule.Order, rule.Action, rule.Protocol, rule.CreatedAt, rule.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	if err := insertACLRuleSources(ctx, db, rule.ID, rule.Sources); err != nil {
		return err
	}
	return insertACLRuleDestinations(ctx, db, rule.ID, rule.Destinations)
}

func (s *Store) CreateACLRule(ctx context.Context, rule *domain.ACLRule) error {
	return createACLRule(ctx, s.db, rule)
}

func (t *Tx) CreateACLRule(ctx context.Context, rule *domain.ACLRule) error {
	return createACLRule(ctx, t.tx, rule)
}

func insertACLRuleSources(ctx context.Context, db dbInterface, ruleID string, sources []string) error {
	for i, src := range sources {
		_, err := db.ExecContext(ctx,
			`INSERT INTO acl_rule_sources (rule_id, source, seq) VALUES ($1, $2, $3)`, ruleID, src, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertACLRuleDestinations(ctx context.Context, db dbInterface, ruleID string, dests []string) error {
	for i, dst := range dests {
		_, err := db.ExecContext(ctx,
			`INSERT INTO acl_rule_destinations (rule_id, destination, seq) VALUES ($1, $2, $3)`, ruleID, dst, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func getACLRuleSources(ctx context.Context, db dbInterface, ruleID string) ([]string, error) {
	var sources []string
	err := db.SelectContext(ctx, &sources,
		`SELECT source FROM acl_rule_sources WHERE rule_id = $1 ORDER BY seq`, ruleID)
	return sources, err
}

func getACLRuleDestinations(ctx context.Context, db dbInterface, ruleID string) ([]string, error) {
	var dests []string
	err := db.SelectContext(ctx, &dests,
		`SELECT destination FROM acl_rule_destinations WHERE rule_id = $1 ORDER BY seq`, ruleID)
	return dests, err
}

func getACLRule(ctx context.Context, db dbInterface, id string) (*domain.ACLRule, error) {
	var rule domain.ACLRule
	err := db.GetContext(ctx, &rule,
		`SELECT id, stack_id, rule_order, action, protocol, created_at, updated_at FROM acl_rules WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rule.Sources, _ = getACLRuleSources(ctx, db, rule.ID)
	rule.Destinations, _ = getACLRuleDestinations(ctx, db, rule.ID)
	return &rule, nil
}

func (s *Store) GetACLRule(ctx context.Context, id string) (*domain.ACLRule, error) {
	return getACLRule(ctx, s.db, id)
}

func (t *Tx) GetACLRule(ctx context.Context, id string) (*domain.ACLRule, error) {
	return getACLRule(ctx, t.tx, id)
}

func listACLRules(ctx context.Context, db dbInterface, stackID string) ([]*domain.ACLRule, error) {
	var rules []*domain.ACLRule
	err := db.SelectContext(ctx, &rules,
		`SELECT id, stack_id, rule_order, action, protocol, created_at, updated_at
		 FROM acl_rules WHERE stack_id = $1 ORDER BY rule_order`, stackID)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		r.Sources, _ = getACLRuleSources(ctx, db, r.ID)
		r.Destinations, _ = getACLRuleDestinations(ctx, db, r.ID)
	}
	return rules, nil
}

func (s *Store) ListACLRules(ctx context.Context, stackID string) ([]*domain.ACLRule, error) {
	return listACLRules(ctx, s.db, stackID)
}

func (t *Tx) ListACLRules(ctx context.Context, stackID string) ([]*domain.ACLRule, error) {
	return listACLRules(ctx, t.tx, stackID)
}

func listAllACLRules(ctx context.Context, db dbInterface) ([]*domain.ACLRule, error) {
	var rules []*domain.ACLRule
	err := db.SelectContext(ctx, &rules,
		`SELECT a.id, a.stack_id, a.rule_order, a.action, a.protocol, a.created_at, a.updated_at
		 FROM acl_rules a JOIN stacks s ON a.stack_id = s.id
		 ORDER BY s.priority, a.rule_order`)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		r.Sources, _ = getACLRuleSources(ctx, db, r.ID)
		r.Destinations, _ = getACLRuleDestinations(ctx, db, r.ID)
	}
	return rules, nil
}

func (s *Store) ListAllACLRules(ctx context.Context) ([]*domain.ACLRule, error) {
	return listAllACLRules(ctx, s.db)
}

func (t *Tx) ListAllACLRules(ctx context.Context) ([]*domain.ACLRule, error) {
	return listAllACLRules(ctx, t.tx)
}

func updateACLRule(ctx context.Context, db dbInterface, rule *domain.ACLRule) error {
	rule.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE acl_rules SET rule_order = $1, action = $2, protocol = $3, updated_at = $4 WHERE id = $5`,
		rule.Order, rule.Action, rule.Protocol, rule.UpdatedAt, rule.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM acl_rule_sources WHERE rule_id = $1`, rule.ID)
	_, _ = db.ExecContext(ctx, `DELETE FROM acl_rule_destinations WHERE rule_id = $1`, rule.ID)
	if err := insertACLRuleSources(ctx, db, rule.ID, rule.Sources); err != nil {
		return err
	}
	return insertACLRuleDestinations(ctx, db, rule.ID, rule.Destinations)
}

func (s *Store) UpdateACLRule(ctx context.Context, rule *domain.ACLRule) error {
	return updateACLRule(ctx, s.db, rule)
}

func (t *Tx) UpdateACLRule(ctx context.Context, rule *domain.ACLRule) error {
	return updateACLRule(ctx, t.tx, rule)
}

func deleteACLRule(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM acl_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteACLRule(ctx context.Context, id string) error {
	return deleteACLRule(ctx, s.db, id)
}

func (t *Tx) DeleteACLRule(ctx context.Context, id string) error {
	return deleteACLRule(ctx, t.tx, id)
}

func deleteAllACLRulesForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM acl_rules WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllACLRulesForStack(ctx context.Context, stackID string) error {
	return deleteAllACLRulesForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllACLRulesForStack(ctx context.Context, stackID string) error {
	return deleteAllACLRulesForStack(ctx, t.tx, stackID)
}

// ============================================
// SSH Rules (similar pattern to ACL Rules)
// ============================================

func createSSHRule(ctx context.Context, db dbInterface, rule *domain.SSHRule) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO ssh_rules (id, stack_id, rule_order, action, check_period, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		rule.ID, rule.StackID, rule.Order, rule.Action, rule.CheckPeriod, rule.CreatedAt, rule.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	if err := insertSSHRuleSources(ctx, db, rule.ID, rule.Sources); err != nil {
		return err
	}
	if err := insertSSHRuleDestinations(ctx, db, rule.ID, rule.Destinations); err != nil {
		return err
	}
	return insertSSHRuleUsers(ctx, db, rule.ID, rule.Users)
}

func (s *Store) CreateSSHRule(ctx context.Context, rule *domain.SSHRule) error {
	return createSSHRule(ctx, s.db, rule)
}

func (t *Tx) CreateSSHRule(ctx context.Context, rule *domain.SSHRule) error {
	return createSSHRule(ctx, t.tx, rule)
}

func insertSSHRuleSources(ctx context.Context, db dbInterface, ruleID string, sources []string) error {
	for i, src := range sources {
		_, err := db.ExecContext(ctx,
			`INSERT INTO ssh_rule_sources (rule_id, source, seq) VALUES ($1, $2, $3)`, ruleID, src, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertSSHRuleDestinations(ctx context.Context, db dbInterface, ruleID string, dests []string) error {
	for i, dst := range dests {
		_, err := db.ExecContext(ctx,
			`INSERT INTO ssh_rule_destinations (rule_id, destination, seq) VALUES ($1, $2, $3)`, ruleID, dst, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertSSHRuleUsers(ctx context.Context, db dbInterface, ruleID string, users []string) error {
	for i, u := range users {
		_, err := db.ExecContext(ctx,
			`INSERT INTO ssh_rule_users (rule_id, user_name, seq) VALUES ($1, $2, $3)`, ruleID, u, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func getSSHRuleSources(ctx context.Context, db dbInterface, ruleID string) ([]string, error) {
	var sources []string
	err := db.SelectContext(ctx, &sources,
		`SELECT source FROM ssh_rule_sources WHERE rule_id = $1 ORDER BY seq`, ruleID)
	return sources, err
}

func getSSHRuleDestinations(ctx context.Context, db dbInterface, ruleID string) ([]string, error) {
	var dests []string
	err := db.SelectContext(ctx, &dests,
		`SELECT destination FROM ssh_rule_destinations WHERE rule_id = $1 ORDER BY seq`, ruleID)
	return dests, err
}

func getSSHRuleUsers(ctx context.Context, db dbInterface, ruleID string) ([]string, error) {
	var users []string
	err := db.SelectContext(ctx, &users,
		`SELECT user_name FROM ssh_rule_users WHERE rule_id = $1 ORDER BY seq`, ruleID)
	return users, err
}

func getSSHRule(ctx context.Context, db dbInterface, id string) (*domain.SSHRule, error) {
	var rule domain.SSHRule
	err := db.GetContext(ctx, &rule,
		`SELECT id, stack_id, rule_order, action, check_period, created_at, updated_at FROM ssh_rules WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rule.Sources, _ = getSSHRuleSources(ctx, db, rule.ID)
	rule.Destinations, _ = getSSHRuleDestinations(ctx, db, rule.ID)
	rule.Users, _ = getSSHRuleUsers(ctx, db, rule.ID)
	return &rule, nil
}

func (s *Store) GetSSHRule(ctx context.Context, id string) (*domain.SSHRule, error) {
	return getSSHRule(ctx, s.db, id)
}

func (t *Tx) GetSSHRule(ctx context.Context, id string) (*domain.SSHRule, error) {
	return getSSHRule(ctx, t.tx, id)
}

func listSSHRules(ctx context.Context, db dbInterface, stackID string) ([]*domain.SSHRule, error) {
	var rules []*domain.SSHRule
	err := db.SelectContext(ctx, &rules,
		`SELECT id, stack_id, rule_order, action, check_period, created_at, updated_at
		 FROM ssh_rules WHERE stack_id = $1 ORDER BY rule_order`, stackID)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		r.Sources, _ = getSSHRuleSources(ctx, db, r.ID)
		r.Destinations, _ = getSSHRuleDestinations(ctx, db, r.ID)
		r.Users, _ = getSSHRuleUsers(ctx, db, r.ID)
	}
	return rules, nil
}

func (s *Store) ListSSHRules(ctx context.Context, stackID string) ([]*domain.SSHRule, error) {
	return listSSHRules(ctx, s.db, stackID)
}

func (t *Tx) ListSSHRules(ctx context.Context, stackID string) ([]*domain.SSHRule, error) {
	return listSSHRules(ctx, t.tx, stackID)
}

func listAllSSHRules(ctx context.Context, db dbInterface) ([]*domain.SSHRule, error) {
	var rules []*domain.SSHRule
	err := db.SelectContext(ctx, &rules,
		`SELECT r.id, r.stack_id, r.rule_order, r.action, r.check_period, r.created_at, r.updated_at
		 FROM ssh_rules r JOIN stacks s ON r.stack_id = s.id
		 ORDER BY s.priority, r.rule_order`)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		r.Sources, _ = getSSHRuleSources(ctx, db, r.ID)
		r.Destinations, _ = getSSHRuleDestinations(ctx, db, r.ID)
		r.Users, _ = getSSHRuleUsers(ctx, db, r.ID)
	}
	return rules, nil
}

func (s *Store) ListAllSSHRules(ctx context.Context) ([]*domain.SSHRule, error) {
	return listAllSSHRules(ctx, s.db)
}

func (t *Tx) ListAllSSHRules(ctx context.Context) ([]*domain.SSHRule, error) {
	return listAllSSHRules(ctx, t.tx)
}

func updateSSHRule(ctx context.Context, db dbInterface, rule *domain.SSHRule) error {
	rule.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE ssh_rules SET rule_order = $1, action = $2, check_period = $3, updated_at = $4 WHERE id = $5`,
		rule.Order, rule.Action, rule.CheckPeriod, rule.UpdatedAt, rule.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM ssh_rule_sources WHERE rule_id = $1`, rule.ID)
	_, _ = db.ExecContext(ctx, `DELETE FROM ssh_rule_destinations WHERE rule_id = $1`, rule.ID)
	_, _ = db.ExecContext(ctx, `DELETE FROM ssh_rule_users WHERE rule_id = $1`, rule.ID)
	if err := insertSSHRuleSources(ctx, db, rule.ID, rule.Sources); err != nil {
		return err
	}
	if err := insertSSHRuleDestinations(ctx, db, rule.ID, rule.Destinations); err != nil {
		return err
	}
	return insertSSHRuleUsers(ctx, db, rule.ID, rule.Users)
}

func (s *Store) UpdateSSHRule(ctx context.Context, rule *domain.SSHRule) error {
	return updateSSHRule(ctx, s.db, rule)
}

func (t *Tx) UpdateSSHRule(ctx context.Context, rule *domain.SSHRule) error {
	return updateSSHRule(ctx, t.tx, rule)
}

func deleteSSHRule(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM ssh_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteSSHRule(ctx context.Context, id string) error {
	return deleteSSHRule(ctx, s.db, id)
}

func (t *Tx) DeleteSSHRule(ctx context.Context, id string) error {
	return deleteSSHRule(ctx, t.tx, id)
}

func deleteAllSSHRulesForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM ssh_rules WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllSSHRulesForStack(ctx context.Context, stackID string) error {
	return deleteAllSSHRulesForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllSSHRulesForStack(ctx context.Context, stackID string) error {
	return deleteAllSSHRulesForStack(ctx, t.tx, stackID)
}

// ============================================
// Grants
// ============================================

func createGrant(ctx context.Context, db dbInterface, grant *domain.Grant) error {
	appJSON, _ := json.Marshal(grant.App)
	_, err := db.ExecContext(ctx,
		`INSERT INTO grants (id, stack_id, rule_order, app_json, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		grant.ID, grant.StackID, grant.Order, string(appJSON), grant.CreatedAt, grant.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	if err := insertGrantSources(ctx, db, grant.ID, grant.Sources); err != nil {
		return err
	}
	if err := insertGrantDestinations(ctx, db, grant.ID, grant.Destinations); err != nil {
		return err
	}
	return insertGrantIPs(ctx, db, grant.ID, grant.IP)
}

func (s *Store) CreateGrant(ctx context.Context, grant *domain.Grant) error {
	return createGrant(ctx, s.db, grant)
}

func (t *Tx) CreateGrant(ctx context.Context, grant *domain.Grant) error {
	return createGrant(ctx, t.tx, grant)
}

func insertGrantSources(ctx context.Context, db dbInterface, grantID string, sources []string) error {
	for i, src := range sources {
		_, err := db.ExecContext(ctx,
			`INSERT INTO grant_sources (grant_id, source, seq) VALUES ($1, $2, $3)`, grantID, src, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertGrantDestinations(ctx context.Context, db dbInterface, grantID string, dests []string) error {
	for i, dst := range dests {
		_, err := db.ExecContext(ctx,
			`INSERT INTO grant_destinations (grant_id, destination, seq) VALUES ($1, $2, $3)`, grantID, dst, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertGrantIPs(ctx context.Context, db dbInterface, grantID string, ips []string) error {
	for i, ip := range ips {
		_, err := db.ExecContext(ctx,
			`INSERT INTO grant_ips (grant_id, ip, seq) VALUES ($1, $2, $3)`, grantID, ip, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func getGrantSources(ctx context.Context, db dbInterface, grantID string) ([]string, error) {
	var sources []string
	err := db.SelectContext(ctx, &sources,
		`SELECT source FROM grant_sources WHERE grant_id = $1 ORDER BY seq`, grantID)
	return sources, err
}

func getGrantDestinations(ctx context.Context, db dbInterface, grantID string) ([]string, error) {
	var dests []string
	err := db.SelectContext(ctx, &dests,
		`SELECT destination FROM grant_destinations WHERE grant_id = $1 ORDER BY seq`, grantID)
	return dests, err
}

func getGrantIPs(ctx context.Context, db dbInterface, grantID string) ([]string, error) {
	var ips []string
	err := db.SelectContext(ctx, &ips,
		`SELECT ip FROM grant_ips WHERE grant_id = $1 ORDER BY seq`, grantID)
	return ips, err
}

type grantRow struct {
	ID        string    `db:"id"`
	StackID   string    `db:"stack_id"`
	Order     int       `db:"rule_order"`
	AppJSON   *string   `db:"app_json"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func rowToGrant(ctx context.Context, db dbInterface, row *grantRow) (*domain.Grant, error) {
	grant := &domain.Grant{
		ID:        row.ID,
		StackID:   row.StackID,
		Order:     row.Order,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
	if row.AppJSON != nil && *row.AppJSON != "" {
		_ = json.Unmarshal([]byte(*row.AppJSON), &grant.App)
	}
	grant.Sources, _ = getGrantSources(ctx, db, grant.ID)
	grant.Destinations, _ = getGrantDestinations(ctx, db, grant.ID)
	grant.IP, _ = getGrantIPs(ctx, db, grant.ID)
	return grant, nil
}

func getGrant(ctx context.Context, db dbInterface, id string) (*domain.Grant, error) {
	var row grantRow
	err := db.GetContext(ctx, &row,
		`SELECT id, stack_id, rule_order, app_json, created_at, updated_at FROM grants WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return rowToGrant(ctx, db, &row)
}

func (s *Store) GetGrant(ctx context.Context, id string) (*domain.Grant, error) {
	return getGrant(ctx, s.db, id)
}

func (t *Tx) GetGrant(ctx context.Context, id string) (*domain.Grant, error) {
	return getGrant(ctx, t.tx, id)
}

func listGrants(ctx context.Context, db dbInterface, stackID string) ([]*domain.Grant, error) {
	var rows []grantRow
	err := db.SelectContext(ctx, &rows,
		`SELECT id, stack_id, rule_order, app_json, created_at, updated_at
		 FROM grants WHERE stack_id = $1 ORDER BY rule_order`, stackID)
	if err != nil {
		return nil, err
	}
	grants := make([]*domain.Grant, 0, len(rows))
	for _, row := range rows {
		g, _ := rowToGrant(ctx, db, &row)
		grants = append(grants, g)
	}
	return grants, nil
}

func (s *Store) ListGrants(ctx context.Context, stackID string) ([]*domain.Grant, error) {
	return listGrants(ctx, s.db, stackID)
}

func (t *Tx) ListGrants(ctx context.Context, stackID string) ([]*domain.Grant, error) {
	return listGrants(ctx, t.tx, stackID)
}

func listAllGrants(ctx context.Context, db dbInterface) ([]*domain.Grant, error) {
	var rows []grantRow
	err := db.SelectContext(ctx, &rows,
		`SELECT g.id, g.stack_id, g.rule_order, g.app_json, g.created_at, g.updated_at
		 FROM grants g JOIN stacks s ON g.stack_id = s.id
		 ORDER BY s.priority, g.rule_order`)
	if err != nil {
		return nil, err
	}
	grants := make([]*domain.Grant, 0, len(rows))
	for _, row := range rows {
		g, _ := rowToGrant(ctx, db, &row)
		grants = append(grants, g)
	}
	return grants, nil
}

func (s *Store) ListAllGrants(ctx context.Context) ([]*domain.Grant, error) {
	return listAllGrants(ctx, s.db)
}

func (t *Tx) ListAllGrants(ctx context.Context) ([]*domain.Grant, error) {
	return listAllGrants(ctx, t.tx)
}

func updateGrant(ctx context.Context, db dbInterface, grant *domain.Grant) error {
	grant.UpdatedAt = time.Now()
	appJSON, _ := json.Marshal(grant.App)
	result, err := db.ExecContext(ctx,
		`UPDATE grants SET rule_order = $1, app_json = $2, updated_at = $3 WHERE id = $4`,
		grant.Order, string(appJSON), grant.UpdatedAt, grant.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM grant_sources WHERE grant_id = $1`, grant.ID)
	_, _ = db.ExecContext(ctx, `DELETE FROM grant_destinations WHERE grant_id = $1`, grant.ID)
	_, _ = db.ExecContext(ctx, `DELETE FROM grant_ips WHERE grant_id = $1`, grant.ID)
	if err := insertGrantSources(ctx, db, grant.ID, grant.Sources); err != nil {
		return err
	}
	if err := insertGrantDestinations(ctx, db, grant.ID, grant.Destinations); err != nil {
		return err
	}
	return insertGrantIPs(ctx, db, grant.ID, grant.IP)
}

func (s *Store) UpdateGrant(ctx context.Context, grant *domain.Grant) error {
	return updateGrant(ctx, s.db, grant)
}

func (t *Tx) UpdateGrant(ctx context.Context, grant *domain.Grant) error {
	return updateGrant(ctx, t.tx, grant)
}

func deleteGrant(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM grants WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteGrant(ctx context.Context, id string) error {
	return deleteGrant(ctx, s.db, id)
}

func (t *Tx) DeleteGrant(ctx context.Context, id string) error {
	return deleteGrant(ctx, t.tx, id)
}

func deleteAllGrantsForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM grants WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllGrantsForStack(ctx context.Context, stackID string) error {
	return deleteAllGrantsForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllGrantsForStack(ctx context.Context, stackID string) error {
	return deleteAllGrantsForStack(ctx, t.tx, stackID)
}

// ============================================
// Auto Approvers
// ============================================

func createAutoApprover(ctx context.Context, db dbInterface, aa *domain.AutoApprover) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO auto_approvers (id, stack_id, type, match, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		aa.ID, aa.StackID, aa.Type, aa.Match, aa.CreatedAt, aa.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	return insertAutoApproverEntries(ctx, db, aa.ID, aa.Approvers)
}

func (s *Store) CreateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error {
	return createAutoApprover(ctx, s.db, aa)
}

func (t *Tx) CreateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error {
	return createAutoApprover(ctx, t.tx, aa)
}

func insertAutoApproverEntries(ctx context.Context, db dbInterface, aaID string, approvers []string) error {
	for _, approver := range approvers {
		_, err := db.ExecContext(ctx,
			`INSERT INTO auto_approver_entries (auto_approver_id, approver) VALUES ($1, $2)`, aaID, approver)
		if err != nil {
			return err
		}
	}
	return nil
}

func getAutoApproverEntries(ctx context.Context, db dbInterface, aaID string) ([]string, error) {
	var approvers []string
	err := db.SelectContext(ctx, &approvers,
		`SELECT approver FROM auto_approver_entries WHERE auto_approver_id = $1`, aaID)
	return approvers, err
}

func getAutoApprover(ctx context.Context, db dbInterface, id string) (*domain.AutoApprover, error) {
	var aa domain.AutoApprover
	err := db.GetContext(ctx, &aa,
		`SELECT id, stack_id, type, match, created_at, updated_at FROM auto_approvers WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	aa.Approvers, _ = getAutoApproverEntries(ctx, db, aa.ID)
	return &aa, nil
}

func (s *Store) GetAutoApprover(ctx context.Context, id string) (*domain.AutoApprover, error) {
	return getAutoApprover(ctx, s.db, id)
}

func (t *Tx) GetAutoApprover(ctx context.Context, id string) (*domain.AutoApprover, error) {
	return getAutoApprover(ctx, t.tx, id)
}

func listAutoApprovers(ctx context.Context, db dbInterface, stackID string) ([]*domain.AutoApprover, error) {
	var aas []*domain.AutoApprover
	err := db.SelectContext(ctx, &aas,
		`SELECT id, stack_id, type, match, created_at, updated_at
		 FROM auto_approvers WHERE stack_id = $1 ORDER BY type, match`, stackID)
	if err != nil {
		return nil, err
	}
	for _, aa := range aas {
		aa.Approvers, _ = getAutoApproverEntries(ctx, db, aa.ID)
	}
	return aas, nil
}

func (s *Store) ListAutoApprovers(ctx context.Context, stackID string) ([]*domain.AutoApprover, error) {
	return listAutoApprovers(ctx, s.db, stackID)
}

func (t *Tx) ListAutoApprovers(ctx context.Context, stackID string) ([]*domain.AutoApprover, error) {
	return listAutoApprovers(ctx, t.tx, stackID)
}

func listAllAutoApprovers(ctx context.Context, db dbInterface) ([]*domain.AutoApprover, error) {
	var aas []*domain.AutoApprover
	err := db.SelectContext(ctx, &aas,
		`SELECT a.id, a.stack_id, a.type, a.match, a.created_at, a.updated_at
		 FROM auto_approvers a JOIN stacks s ON a.stack_id = s.id
		 ORDER BY s.priority, a.type, a.match`)
	if err != nil {
		return nil, err
	}
	for _, aa := range aas {
		aa.Approvers, _ = getAutoApproverEntries(ctx, db, aa.ID)
	}
	return aas, nil
}

func (s *Store) ListAllAutoApprovers(ctx context.Context) ([]*domain.AutoApprover, error) {
	return listAllAutoApprovers(ctx, s.db)
}

func (t *Tx) ListAllAutoApprovers(ctx context.Context) ([]*domain.AutoApprover, error) {
	return listAllAutoApprovers(ctx, t.tx)
}

func updateAutoApprover(ctx context.Context, db dbInterface, aa *domain.AutoApprover) error {
	aa.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE auto_approvers SET updated_at = $1 WHERE id = $2`, aa.UpdatedAt, aa.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM auto_approver_entries WHERE auto_approver_id = $1`, aa.ID)
	return insertAutoApproverEntries(ctx, db, aa.ID, aa.Approvers)
}

func (s *Store) UpdateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error {
	return updateAutoApprover(ctx, s.db, aa)
}

func (t *Tx) UpdateAutoApprover(ctx context.Context, aa *domain.AutoApprover) error {
	return updateAutoApprover(ctx, t.tx, aa)
}

func deleteAutoApprover(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM auto_approvers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAutoApprover(ctx context.Context, id string) error {
	return deleteAutoApprover(ctx, s.db, id)
}

func (t *Tx) DeleteAutoApprover(ctx context.Context, id string) error {
	return deleteAutoApprover(ctx, t.tx, id)
}

func deleteAllAutoApproversForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM auto_approvers WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllAutoApproversForStack(ctx context.Context, stackID string) error {
	return deleteAllAutoApproversForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllAutoApproversForStack(ctx context.Context, stackID string) error {
	return deleteAllAutoApproversForStack(ctx, t.tx, stackID)
}

// ============================================
// Node Attributes
// ============================================

func createNodeAttr(ctx context.Context, db dbInterface, attr *domain.NodeAttr) error {
	appJSON, _ := json.Marshal(attr.App)
	_, err := db.ExecContext(ctx,
		`INSERT INTO node_attrs (id, stack_id, rule_order, app_json, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		attr.ID, attr.StackID, attr.Order, string(appJSON), attr.CreatedAt, attr.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	if err := insertNodeAttrTargets(ctx, db, attr.ID, attr.Target); err != nil {
		return err
	}
	return insertNodeAttrAttrs(ctx, db, attr.ID, attr.Attr)
}

func (s *Store) CreateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error {
	return createNodeAttr(ctx, s.db, attr)
}

func (t *Tx) CreateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error {
	return createNodeAttr(ctx, t.tx, attr)
}

func insertNodeAttrTargets(ctx context.Context, db dbInterface, attrID string, targets []string) error {
	for i, target := range targets {
		_, err := db.ExecContext(ctx,
			`INSERT INTO node_attr_targets (node_attr_id, target, seq) VALUES ($1, $2, $3)`, attrID, target, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertNodeAttrAttrs(ctx context.Context, db dbInterface, attrID string, attrs []string) error {
	for i, a := range attrs {
		_, err := db.ExecContext(ctx,
			`INSERT INTO node_attr_attrs (node_attr_id, attr, seq) VALUES ($1, $2, $3)`, attrID, a, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func getNodeAttrTargets(ctx context.Context, db dbInterface, attrID string) ([]string, error) {
	var targets []string
	err := db.SelectContext(ctx, &targets,
		`SELECT target FROM node_attr_targets WHERE node_attr_id = $1 ORDER BY seq`, attrID)
	return targets, err
}

func getNodeAttrAttrs(ctx context.Context, db dbInterface, attrID string) ([]string, error) {
	var attrs []string
	err := db.SelectContext(ctx, &attrs,
		`SELECT attr FROM node_attr_attrs WHERE node_attr_id = $1 ORDER BY seq`, attrID)
	return attrs, err
}

type nodeAttrRow struct {
	ID        string    `db:"id"`
	StackID   string    `db:"stack_id"`
	Order     int       `db:"rule_order"`
	AppJSON   *string   `db:"app_json"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func rowToNodeAttr(ctx context.Context, db dbInterface, row *nodeAttrRow) (*domain.NodeAttr, error) {
	attr := &domain.NodeAttr{
		ID:        row.ID,
		StackID:   row.StackID,
		Order:     row.Order,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
	if row.AppJSON != nil && *row.AppJSON != "" {
		_ = json.Unmarshal([]byte(*row.AppJSON), &attr.App)
	}
	attr.Target, _ = getNodeAttrTargets(ctx, db, attr.ID)
	attr.Attr, _ = getNodeAttrAttrs(ctx, db, attr.ID)
	return attr, nil
}

func getNodeAttr(ctx context.Context, db dbInterface, id string) (*domain.NodeAttr, error) {
	var row nodeAttrRow
	err := db.GetContext(ctx, &row,
		`SELECT id, stack_id, rule_order, app_json, created_at, updated_at FROM node_attrs WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return rowToNodeAttr(ctx, db, &row)
}

func (s *Store) GetNodeAttr(ctx context.Context, id string) (*domain.NodeAttr, error) {
	return getNodeAttr(ctx, s.db, id)
}

func (t *Tx) GetNodeAttr(ctx context.Context, id string) (*domain.NodeAttr, error) {
	return getNodeAttr(ctx, t.tx, id)
}

func listNodeAttrs(ctx context.Context, db dbInterface, stackID string) ([]*domain.NodeAttr, error) {
	var rows []nodeAttrRow
	err := db.SelectContext(ctx, &rows,
		`SELECT id, stack_id, rule_order, app_json, created_at, updated_at
		 FROM node_attrs WHERE stack_id = $1 ORDER BY rule_order`, stackID)
	if err != nil {
		return nil, err
	}
	attrs := make([]*domain.NodeAttr, 0, len(rows))
	for _, row := range rows {
		a, _ := rowToNodeAttr(ctx, db, &row)
		attrs = append(attrs, a)
	}
	return attrs, nil
}

func (s *Store) ListNodeAttrs(ctx context.Context, stackID string) ([]*domain.NodeAttr, error) {
	return listNodeAttrs(ctx, s.db, stackID)
}

func (t *Tx) ListNodeAttrs(ctx context.Context, stackID string) ([]*domain.NodeAttr, error) {
	return listNodeAttrs(ctx, t.tx, stackID)
}

func listAllNodeAttrs(ctx context.Context, db dbInterface) ([]*domain.NodeAttr, error) {
	var rows []nodeAttrRow
	err := db.SelectContext(ctx, &rows,
		`SELECT n.id, n.stack_id, n.rule_order, n.app_json, n.created_at, n.updated_at
		 FROM node_attrs n JOIN stacks s ON n.stack_id = s.id
		 ORDER BY s.priority, n.rule_order`)
	if err != nil {
		return nil, err
	}
	attrs := make([]*domain.NodeAttr, 0, len(rows))
	for _, row := range rows {
		a, _ := rowToNodeAttr(ctx, db, &row)
		attrs = append(attrs, a)
	}
	return attrs, nil
}

func (s *Store) ListAllNodeAttrs(ctx context.Context) ([]*domain.NodeAttr, error) {
	return listAllNodeAttrs(ctx, s.db)
}

func (t *Tx) ListAllNodeAttrs(ctx context.Context) ([]*domain.NodeAttr, error) {
	return listAllNodeAttrs(ctx, t.tx)
}

func updateNodeAttr(ctx context.Context, db dbInterface, attr *domain.NodeAttr) error {
	attr.UpdatedAt = time.Now()
	appJSON, _ := json.Marshal(attr.App)
	result, err := db.ExecContext(ctx,
		`UPDATE node_attrs SET rule_order = $1, app_json = $2, updated_at = $3 WHERE id = $4`,
		attr.Order, string(appJSON), attr.UpdatedAt, attr.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM node_attr_targets WHERE node_attr_id = $1`, attr.ID)
	_, _ = db.ExecContext(ctx, `DELETE FROM node_attr_attrs WHERE node_attr_id = $1`, attr.ID)
	if err := insertNodeAttrTargets(ctx, db, attr.ID, attr.Target); err != nil {
		return err
	}
	return insertNodeAttrAttrs(ctx, db, attr.ID, attr.Attr)
}

func (s *Store) UpdateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error {
	return updateNodeAttr(ctx, s.db, attr)
}

func (t *Tx) UpdateNodeAttr(ctx context.Context, attr *domain.NodeAttr) error {
	return updateNodeAttr(ctx, t.tx, attr)
}

func deleteNodeAttr(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM node_attrs WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteNodeAttr(ctx context.Context, id string) error {
	return deleteNodeAttr(ctx, s.db, id)
}

func (t *Tx) DeleteNodeAttr(ctx context.Context, id string) error {
	return deleteNodeAttr(ctx, t.tx, id)
}

func deleteAllNodeAttrsForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM node_attrs WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllNodeAttrsForStack(ctx context.Context, stackID string) error {
	return deleteAllNodeAttrsForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllNodeAttrsForStack(ctx context.Context, stackID string) error {
	return deleteAllNodeAttrsForStack(ctx, t.tx, stackID)
}

// ============================================
// Postures
// ============================================

func createPosture(ctx context.Context, db dbInterface, posture *domain.Posture) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO postures (id, stack_id, name, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		posture.ID, posture.StackID, posture.Name, posture.CreatedAt, posture.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	return insertPostureRules(ctx, db, posture.ID, posture.Rules)
}

func (s *Store) CreatePosture(ctx context.Context, posture *domain.Posture) error {
	return createPosture(ctx, s.db, posture)
}

func (t *Tx) CreatePosture(ctx context.Context, posture *domain.Posture) error {
	return createPosture(ctx, t.tx, posture)
}

func insertPostureRules(ctx context.Context, db dbInterface, postureID string, rules []string) error {
	for i, rule := range rules {
		_, err := db.ExecContext(ctx,
			`INSERT INTO posture_rules (posture_id, rule, seq) VALUES ($1, $2, $3)`, postureID, rule, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func getPostureRules(ctx context.Context, db dbInterface, postureID string) ([]string, error) {
	var rules []string
	err := db.SelectContext(ctx, &rules,
		`SELECT rule FROM posture_rules WHERE posture_id = $1 ORDER BY seq`, postureID)
	return rules, err
}

func getPosture(ctx context.Context, db dbInterface, stackID, name string) (*domain.Posture, error) {
	var posture domain.Posture
	err := db.GetContext(ctx, &posture,
		`SELECT id, stack_id, name, created_at, updated_at FROM postures WHERE stack_id = $1 AND name = $2`, stackID, name)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	posture.Rules, _ = getPostureRules(ctx, db, posture.ID)
	return &posture, nil
}

func (s *Store) GetPosture(ctx context.Context, stackID, name string) (*domain.Posture, error) {
	return getPosture(ctx, s.db, stackID, name)
}

func (t *Tx) GetPosture(ctx context.Context, stackID, name string) (*domain.Posture, error) {
	return getPosture(ctx, t.tx, stackID, name)
}

func listPostures(ctx context.Context, db dbInterface, stackID string) ([]*domain.Posture, error) {
	var postures []*domain.Posture
	err := db.SelectContext(ctx, &postures,
		`SELECT id, stack_id, name, created_at, updated_at FROM postures WHERE stack_id = $1 ORDER BY name`, stackID)
	if err != nil {
		return nil, err
	}
	for _, p := range postures {
		p.Rules, _ = getPostureRules(ctx, db, p.ID)
	}
	return postures, nil
}

func (s *Store) ListPostures(ctx context.Context, stackID string) ([]*domain.Posture, error) {
	return listPostures(ctx, s.db, stackID)
}

func (t *Tx) ListPostures(ctx context.Context, stackID string) ([]*domain.Posture, error) {
	return listPostures(ctx, t.tx, stackID)
}

func listAllPostures(ctx context.Context, db dbInterface) ([]*domain.Posture, error) {
	var postures []*domain.Posture
	err := db.SelectContext(ctx, &postures,
		`SELECT p.id, p.stack_id, p.name, p.created_at, p.updated_at
		 FROM postures p JOIN stacks s ON p.stack_id = s.id
		 ORDER BY s.priority, p.name`)
	if err != nil {
		return nil, err
	}
	for _, p := range postures {
		p.Rules, _ = getPostureRules(ctx, db, p.ID)
	}
	return postures, nil
}

func (s *Store) ListAllPostures(ctx context.Context) ([]*domain.Posture, error) {
	return listAllPostures(ctx, s.db)
}

func (t *Tx) ListAllPostures(ctx context.Context) ([]*domain.Posture, error) {
	return listAllPostures(ctx, t.tx)
}

func updatePosture(ctx context.Context, db dbInterface, posture *domain.Posture) error {
	posture.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE postures SET updated_at = $1 WHERE id = $2`, posture.UpdatedAt, posture.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM posture_rules WHERE posture_id = $1`, posture.ID)
	return insertPostureRules(ctx, db, posture.ID, posture.Rules)
}

func (s *Store) UpdatePosture(ctx context.Context, posture *domain.Posture) error {
	return updatePosture(ctx, s.db, posture)
}

func (t *Tx) UpdatePosture(ctx context.Context, posture *domain.Posture) error {
	return updatePosture(ctx, t.tx, posture)
}

func deletePosture(ctx context.Context, db dbInterface, stackID, name string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM postures WHERE stack_id = $1 AND name = $2`, stackID, name)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeletePosture(ctx context.Context, stackID, name string) error {
	return deletePosture(ctx, s.db, stackID, name)
}

func (t *Tx) DeletePosture(ctx context.Context, stackID, name string) error {
	return deletePosture(ctx, t.tx, stackID, name)
}

func getPostureByID(ctx context.Context, db dbInterface, id string) (*domain.Posture, error) {
	var posture domain.Posture
	err := db.GetContext(ctx, &posture,
		`SELECT id, stack_id, name, created_at, updated_at FROM postures WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	posture.Rules, _ = getPostureRules(ctx, db, posture.ID)
	return &posture, nil
}

func (s *Store) GetPostureByID(ctx context.Context, id string) (*domain.Posture, error) {
	return getPostureByID(ctx, s.db, id)
}

func (t *Tx) GetPostureByID(ctx context.Context, id string) (*domain.Posture, error) {
	return getPostureByID(ctx, t.tx, id)
}

func deletePostureByID(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM postures WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeletePostureByID(ctx context.Context, id string) error {
	return deletePostureByID(ctx, s.db, id)
}

func (t *Tx) DeletePostureByID(ctx context.Context, id string) error {
	return deletePostureByID(ctx, t.tx, id)
}

func deleteAllPosturesForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM postures WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllPosturesForStack(ctx context.Context, stackID string) error {
	return deleteAllPosturesForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllPosturesForStack(ctx context.Context, stackID string) error {
	return deleteAllPosturesForStack(ctx, t.tx, stackID)
}

// ============================================
// IP Sets
// ============================================

func createIPSet(ctx context.Context, db dbInterface, ipset *domain.IPSet) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO ip_sets (id, stack_id, name, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		ipset.ID, ipset.StackID, ipset.Name, ipset.CreatedAt, ipset.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	return insertIPSetAddresses(ctx, db, ipset.ID, ipset.Addresses)
}

func (s *Store) CreateIPSet(ctx context.Context, ipset *domain.IPSet) error {
	return createIPSet(ctx, s.db, ipset)
}

func (t *Tx) CreateIPSet(ctx context.Context, ipset *domain.IPSet) error {
	return createIPSet(ctx, t.tx, ipset)
}

func insertIPSetAddresses(ctx context.Context, db dbInterface, ipsetID string, addrs []string) error {
	for i, addr := range addrs {
		_, err := db.ExecContext(ctx,
			`INSERT INTO ip_set_addresses (ip_set_id, address, seq) VALUES ($1, $2, $3)`, ipsetID, addr, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func getIPSetAddresses(ctx context.Context, db dbInterface, ipsetID string) ([]string, error) {
	var addrs []string
	err := db.SelectContext(ctx, &addrs,
		`SELECT address FROM ip_set_addresses WHERE ip_set_id = $1 ORDER BY seq`, ipsetID)
	return addrs, err
}

func getIPSet(ctx context.Context, db dbInterface, stackID, name string) (*domain.IPSet, error) {
	var ipset domain.IPSet
	err := db.GetContext(ctx, &ipset,
		`SELECT id, stack_id, name, created_at, updated_at FROM ip_sets WHERE stack_id = $1 AND name = $2`, stackID, name)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ipset.Addresses, _ = getIPSetAddresses(ctx, db, ipset.ID)
	return &ipset, nil
}

func (s *Store) GetIPSet(ctx context.Context, stackID, name string) (*domain.IPSet, error) {
	return getIPSet(ctx, s.db, stackID, name)
}

func (t *Tx) GetIPSet(ctx context.Context, stackID, name string) (*domain.IPSet, error) {
	return getIPSet(ctx, t.tx, stackID, name)
}

func listIPSets(ctx context.Context, db dbInterface, stackID string) ([]*domain.IPSet, error) {
	var ipsets []*domain.IPSet
	err := db.SelectContext(ctx, &ipsets,
		`SELECT id, stack_id, name, created_at, updated_at FROM ip_sets WHERE stack_id = $1 ORDER BY name`, stackID)
	if err != nil {
		return nil, err
	}
	for _, is := range ipsets {
		is.Addresses, _ = getIPSetAddresses(ctx, db, is.ID)
	}
	return ipsets, nil
}

func (s *Store) ListIPSets(ctx context.Context, stackID string) ([]*domain.IPSet, error) {
	return listIPSets(ctx, s.db, stackID)
}

func (t *Tx) ListIPSets(ctx context.Context, stackID string) ([]*domain.IPSet, error) {
	return listIPSets(ctx, t.tx, stackID)
}

func listAllIPSets(ctx context.Context, db dbInterface) ([]*domain.IPSet, error) {
	var ipsets []*domain.IPSet
	err := db.SelectContext(ctx, &ipsets,
		`SELECT i.id, i.stack_id, i.name, i.created_at, i.updated_at
		 FROM ip_sets i JOIN stacks s ON i.stack_id = s.id
		 ORDER BY s.priority, i.name`)
	if err != nil {
		return nil, err
	}
	for _, is := range ipsets {
		is.Addresses, _ = getIPSetAddresses(ctx, db, is.ID)
	}
	return ipsets, nil
}

func (s *Store) ListAllIPSets(ctx context.Context) ([]*domain.IPSet, error) {
	return listAllIPSets(ctx, s.db)
}

func (t *Tx) ListAllIPSets(ctx context.Context) ([]*domain.IPSet, error) {
	return listAllIPSets(ctx, t.tx)
}

func updateIPSet(ctx context.Context, db dbInterface, ipset *domain.IPSet) error {
	ipset.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE ip_sets SET updated_at = $1 WHERE id = $2`, ipset.UpdatedAt, ipset.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM ip_set_addresses WHERE ip_set_id = $1`, ipset.ID)
	return insertIPSetAddresses(ctx, db, ipset.ID, ipset.Addresses)
}

func (s *Store) UpdateIPSet(ctx context.Context, ipset *domain.IPSet) error {
	return updateIPSet(ctx, s.db, ipset)
}

func (t *Tx) UpdateIPSet(ctx context.Context, ipset *domain.IPSet) error {
	return updateIPSet(ctx, t.tx, ipset)
}

func deleteIPSet(ctx context.Context, db dbInterface, stackID, name string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM ip_sets WHERE stack_id = $1 AND name = $2`, stackID, name)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteIPSet(ctx context.Context, stackID, name string) error {
	return deleteIPSet(ctx, s.db, stackID, name)
}

func (t *Tx) DeleteIPSet(ctx context.Context, stackID, name string) error {
	return deleteIPSet(ctx, t.tx, stackID, name)
}

func getIPSetByID(ctx context.Context, db dbInterface, id string) (*domain.IPSet, error) {
	var ipset domain.IPSet
	err := db.GetContext(ctx, &ipset,
		`SELECT id, stack_id, name, created_at, updated_at FROM ip_sets WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ipset.Addresses, _ = getIPSetAddresses(ctx, db, ipset.ID)
	return &ipset, nil
}

func (s *Store) GetIPSetByID(ctx context.Context, id string) (*domain.IPSet, error) {
	return getIPSetByID(ctx, s.db, id)
}

func (t *Tx) GetIPSetByID(ctx context.Context, id string) (*domain.IPSet, error) {
	return getIPSetByID(ctx, t.tx, id)
}

func deleteIPSetByID(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM ip_sets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteIPSetByID(ctx context.Context, id string) error {
	return deleteIPSetByID(ctx, s.db, id)
}

func (t *Tx) DeleteIPSetByID(ctx context.Context, id string) error {
	return deleteIPSetByID(ctx, t.tx, id)
}

func deleteAllIPSetsForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM ip_sets WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllIPSetsForStack(ctx context.Context, stackID string) error {
	return deleteAllIPSetsForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllIPSetsForStack(ctx context.Context, stackID string) error {
	return deleteAllIPSetsForStack(ctx, t.tx, stackID)
}

// ============================================
// ACL Tests
// ============================================

func createACLTest(ctx context.Context, db dbInterface, test *domain.ACLTest) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO acl_tests (id, stack_id, rule_order, src, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		test.ID, test.StackID, test.Order, test.Source, test.CreatedAt, test.UpdatedAt)
	if err != nil {
		return wrapUniqueError(err)
	}
	if err := insertACLTestAccepts(ctx, db, test.ID, test.Accept); err != nil {
		return err
	}
	return insertACLTestDenies(ctx, db, test.ID, test.Deny)
}

func (s *Store) CreateACLTest(ctx context.Context, test *domain.ACLTest) error {
	return createACLTest(ctx, s.db, test)
}

func (t *Tx) CreateACLTest(ctx context.Context, test *domain.ACLTest) error {
	return createACLTest(ctx, t.tx, test)
}

func insertACLTestAccepts(ctx context.Context, db dbInterface, testID string, accepts []string) error {
	for i, a := range accepts {
		_, err := db.ExecContext(ctx,
			`INSERT INTO acl_test_accepts (test_id, accept, seq) VALUES ($1, $2, $3)`, testID, a, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertACLTestDenies(ctx context.Context, db dbInterface, testID string, denies []string) error {
	for i, d := range denies {
		_, err := db.ExecContext(ctx,
			`INSERT INTO acl_test_denies (test_id, deny, seq) VALUES ($1, $2, $3)`, testID, d, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func getACLTestAccepts(ctx context.Context, db dbInterface, testID string) ([]string, error) {
	var accepts []string
	err := db.SelectContext(ctx, &accepts,
		`SELECT accept FROM acl_test_accepts WHERE test_id = $1 ORDER BY seq`, testID)
	return accepts, err
}

func getACLTestDenies(ctx context.Context, db dbInterface, testID string) ([]string, error) {
	var denies []string
	err := db.SelectContext(ctx, &denies,
		`SELECT deny FROM acl_test_denies WHERE test_id = $1 ORDER BY seq`, testID)
	return denies, err
}

func getACLTest(ctx context.Context, db dbInterface, id string) (*domain.ACLTest, error) {
	var test domain.ACLTest
	err := db.GetContext(ctx, &test,
		`SELECT id, stack_id, rule_order, src, created_at, updated_at FROM acl_tests WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	test.Accept, _ = getACLTestAccepts(ctx, db, test.ID)
	test.Deny, _ = getACLTestDenies(ctx, db, test.ID)
	return &test, nil
}

func (s *Store) GetACLTest(ctx context.Context, id string) (*domain.ACLTest, error) {
	return getACLTest(ctx, s.db, id)
}

func (t *Tx) GetACLTest(ctx context.Context, id string) (*domain.ACLTest, error) {
	return getACLTest(ctx, t.tx, id)
}

func listACLTests(ctx context.Context, db dbInterface, stackID string) ([]*domain.ACLTest, error) {
	var tests []*domain.ACLTest
	err := db.SelectContext(ctx, &tests,
		`SELECT id, stack_id, rule_order, src, created_at, updated_at
		 FROM acl_tests WHERE stack_id = $1 ORDER BY rule_order`, stackID)
	if err != nil {
		return nil, err
	}
	for _, t := range tests {
		t.Accept, _ = getACLTestAccepts(ctx, db, t.ID)
		t.Deny, _ = getACLTestDenies(ctx, db, t.ID)
	}
	return tests, nil
}

func (s *Store) ListACLTests(ctx context.Context, stackID string) ([]*domain.ACLTest, error) {
	return listACLTests(ctx, s.db, stackID)
}

func (t *Tx) ListACLTests(ctx context.Context, stackID string) ([]*domain.ACLTest, error) {
	return listACLTests(ctx, t.tx, stackID)
}

func listAllACLTests(ctx context.Context, db dbInterface) ([]*domain.ACLTest, error) {
	var tests []*domain.ACLTest
	err := db.SelectContext(ctx, &tests,
		`SELECT t.id, t.stack_id, t.rule_order, t.src, t.created_at, t.updated_at
		 FROM acl_tests t JOIN stacks s ON t.stack_id = s.id
		 ORDER BY s.priority, t.rule_order`)
	if err != nil {
		return nil, err
	}
	for _, t := range tests {
		t.Accept, _ = getACLTestAccepts(ctx, db, t.ID)
		t.Deny, _ = getACLTestDenies(ctx, db, t.ID)
	}
	return tests, nil
}

func (s *Store) ListAllACLTests(ctx context.Context) ([]*domain.ACLTest, error) {
	return listAllACLTests(ctx, s.db)
}

func (t *Tx) ListAllACLTests(ctx context.Context) ([]*domain.ACLTest, error) {
	return listAllACLTests(ctx, t.tx)
}

func updateACLTest(ctx context.Context, db dbInterface, test *domain.ACLTest) error {
	test.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx,
		`UPDATE acl_tests SET rule_order = $1, src = $2, updated_at = $3 WHERE id = $4`,
		test.Order, test.Source, test.UpdatedAt, test.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM acl_test_accepts WHERE test_id = $1`, test.ID)
	_, _ = db.ExecContext(ctx, `DELETE FROM acl_test_denies WHERE test_id = $1`, test.ID)
	if err := insertACLTestAccepts(ctx, db, test.ID, test.Accept); err != nil {
		return err
	}
	return insertACLTestDenies(ctx, db, test.ID, test.Deny)
}

func (s *Store) UpdateACLTest(ctx context.Context, test *domain.ACLTest) error {
	return updateACLTest(ctx, s.db, test)
}

func (t *Tx) UpdateACLTest(ctx context.Context, test *domain.ACLTest) error {
	return updateACLTest(ctx, t.tx, test)
}

func deleteACLTest(ctx context.Context, db dbInterface, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM acl_tests WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteACLTest(ctx context.Context, id string) error {
	return deleteACLTest(ctx, s.db, id)
}

func (t *Tx) DeleteACLTest(ctx context.Context, id string) error {
	return deleteACLTest(ctx, t.tx, id)
}

func deleteAllACLTestsForStack(ctx context.Context, db dbInterface, stackID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM acl_tests WHERE stack_id = $1`, stackID)
	return err
}

func (s *Store) DeleteAllACLTestsForStack(ctx context.Context, stackID string) error {
	return deleteAllACLTestsForStack(ctx, s.db, stackID)
}

func (t *Tx) DeleteAllACLTestsForStack(ctx context.Context, stackID string) error {
	return deleteAllACLTestsForStack(ctx, t.tx, stackID)
}

// ============================================
// Policy Versions
// ============================================

func createPolicyVersion(ctx context.Context, db dbInterface, version *domain.PolicyVersion) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO policy_versions (id, version_number, rendered_policy, tailscale_etag, push_status, push_error, created_at, pushed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		version.ID, version.VersionNumber, version.RenderedPolicy, version.TailscaleETag,
		version.PushStatus, version.PushError, version.CreatedAt, version.PushedAt)
	return wrapUniqueError(err)
}

func (s *Store) CreatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error {
	return createPolicyVersion(ctx, s.db, version)
}

func (t *Tx) CreatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error {
	return createPolicyVersion(ctx, t.tx, version)
}

func getPolicyVersion(ctx context.Context, db dbInterface, id string) (*domain.PolicyVersion, error) {
	var version domain.PolicyVersion
	err := db.GetContext(ctx, &version,
		`SELECT id, version_number, rendered_policy, tailscale_etag, push_status, push_error, created_at, pushed_at
		 FROM policy_versions WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return &version, err
}

func (s *Store) GetPolicyVersion(ctx context.Context, id string) (*domain.PolicyVersion, error) {
	return getPolicyVersion(ctx, s.db, id)
}

func (t *Tx) GetPolicyVersion(ctx context.Context, id string) (*domain.PolicyVersion, error) {
	return getPolicyVersion(ctx, t.tx, id)
}

func getLatestPolicyVersion(ctx context.Context, db dbInterface) (*domain.PolicyVersion, error) {
	var version domain.PolicyVersion
	err := db.GetContext(ctx, &version,
		`SELECT id, version_number, rendered_policy, tailscale_etag, push_status, push_error, created_at, pushed_at
		 FROM policy_versions ORDER BY version_number DESC LIMIT 1`)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return &version, err
}

func (s *Store) GetLatestPolicyVersion(ctx context.Context) (*domain.PolicyVersion, error) {
	return getLatestPolicyVersion(ctx, s.db)
}

func (t *Tx) GetLatestPolicyVersion(ctx context.Context) (*domain.PolicyVersion, error) {
	return getLatestPolicyVersion(ctx, t.tx)
}

func listPolicyVersions(ctx context.Context, db dbInterface, limit, offset int) ([]*domain.PolicyVersion, error) {
	var versions []*domain.PolicyVersion
	err := db.SelectContext(ctx, &versions,
		`SELECT id, version_number, rendered_policy, tailscale_etag, push_status, push_error, created_at, pushed_at
		 FROM policy_versions ORDER BY version_number DESC LIMIT $1 OFFSET $2`, limit, offset)
	return versions, err
}

func (s *Store) ListPolicyVersions(ctx context.Context, limit, offset int) ([]*domain.PolicyVersion, error) {
	return listPolicyVersions(ctx, s.db, limit, offset)
}

func (t *Tx) ListPolicyVersions(ctx context.Context, limit, offset int) ([]*domain.PolicyVersion, error) {
	return listPolicyVersions(ctx, t.tx, limit, offset)
}

func updatePolicyVersion(ctx context.Context, db dbInterface, version *domain.PolicyVersion) error {
	result, err := db.ExecContext(ctx,
		`UPDATE policy_versions SET tailscale_etag = $1, push_status = $2, push_error = $3, pushed_at = $4 WHERE id = $5`,
		version.TailscaleETag, version.PushStatus, version.PushError, version.PushedAt, version.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) UpdatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error {
	return updatePolicyVersion(ctx, s.db, version)
}

func (t *Tx) UpdatePolicyVersion(ctx context.Context, version *domain.PolicyVersion) error {
	return updatePolicyVersion(ctx, t.tx, version)
}
