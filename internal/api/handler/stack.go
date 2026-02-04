package handler

import (
	"net/http"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/go-chi/chi/v5"
)

// StackHandler handles stack endpoints.
type StackHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewStackHandler creates a new StackHandler.
func NewStackHandler(store storage.Storage, syncService *service.SyncService) *StackHandler {
	return &StackHandler{store: store, syncService: syncService}
}

// Create creates a new stack.
func (h *StackHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateStackRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	now := time.Now()
	stack := &domain.Stack{
		ID:          generateID(),
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if stack.Priority == 0 {
		stack.Priority = 100 // Default priority
	}

	if err := h.store.CreateStack(r.Context(), stack); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusCreated, stack, h.syncService)
}

// List lists all stacks.
func (h *StackHandler) List(w http.ResponseWriter, r *http.Request) {
	stacks, err := h.store.ListStacks(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, stacks)
}

// Get gets a stack by ID.
func (h *StackHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "stack_id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	stack, err := h.store.GetStack(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, stack)
}

// Update updates a stack.
func (h *StackHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "stack_id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	var req domain.UpdateStackRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	stack, err := h.store.GetStack(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if req.Name != nil {
		stack.Name = *req.Name
	}
	if req.Description != nil {
		stack.Description = *req.Description
	}
	if req.Priority != nil {
		stack.Priority = *req.Priority
	}

	if err := h.store.UpdateStack(r.Context(), stack); err != nil {
		handleError(w, err)
		return
	}

	// Priority changes affect merge order, trigger sync
	respondMutation(w, r, http.StatusOK, stack, h.syncService)
}

// Delete deletes a stack and all its resources.
func (h *StackHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "stack_id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if err := h.store.DeleteStack(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}

// ReplaceState replaces all resources for a stack with the provided state.
func (h *StackHandler) ReplaceState(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	// Verify stack exists
	_, err := h.store.GetStack(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	var state domain.StackState
	if err := decodeJSON(r, &state); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()

	// Start a transaction
	tx, err := h.store.BeginTx(ctx)
	if err != nil {
		handleError(w, err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Delete all existing resources for this stack
	if err := tx.DeleteAllGroupsForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllTagOwnersForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllHostsForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllACLRulesForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllSSHRulesForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllGrantsForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllAutoApproversForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllNodeAttrsForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllPosturesForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllIPSetsForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}
	if err := tx.DeleteAllACLTestsForStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}

	now := time.Now()

	// Create new resources
	for _, g := range state.Groups {
		group := &domain.Group{
			ID:        generateID(),
			StackID:   stackID,
			Name:      g.Name,
			Members:   g.Members,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.CreateGroup(ctx, group); err != nil {
			handleError(w, err)
			return
		}
	}

	for _, t := range state.TagOwners {
		tagOwner := &domain.TagOwner{
			ID:        generateID(),
			StackID:   stackID,
			Tag:       t.Tag,
			Owners:    t.Owners,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.CreateTagOwner(ctx, tagOwner); err != nil {
			handleError(w, err)
			return
		}
	}

	for _, h := range state.Hosts {
		host := &domain.Host{
			ID:        generateID(),
			StackID:   stackID,
			Name:      h.Name,
			Address:   h.Address,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.CreateHost(ctx, host); err != nil {
			handleError(w, err)
			return
		}
	}

	for i, a := range state.ACLs {
		rule := &domain.ACLRule{
			ID:           generateID(),
			StackID:      stackID,
			Order:        i,
			Action:       a.Action,
			Protocol:     a.Protocol,
			Sources:      a.Sources,
			Destinations: a.Destinations,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if a.Order != 0 {
			rule.Order = a.Order
		}
		if err := tx.CreateACLRule(ctx, rule); err != nil {
			handleError(w, err)
			return
		}
	}

	for i, s := range state.SSHRules {
		rule := &domain.SSHRule{
			ID:           generateID(),
			StackID:      stackID,
			Order:        i,
			Action:       s.Action,
			Sources:      s.Sources,
			Destinations: s.Destinations,
			Users:        s.Users,
			CheckPeriod:  s.CheckPeriod,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if s.Order != 0 {
			rule.Order = s.Order
		}
		if err := tx.CreateSSHRule(ctx, rule); err != nil {
			handleError(w, err)
			return
		}
	}

	for i, g := range state.Grants {
		grant := &domain.Grant{
			ID:           generateID(),
			StackID:      stackID,
			Order:        i,
			Sources:      g.Sources,
			Destinations: g.Destinations,
			IP:           g.IP,
			App:          g.App,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if g.Order != 0 {
			grant.Order = g.Order
		}
		if err := tx.CreateGrant(ctx, grant); err != nil {
			handleError(w, err)
			return
		}
	}

	for _, aa := range state.AutoApprovers {
		autoApprover := &domain.AutoApprover{
			ID:        generateID(),
			StackID:   stackID,
			Type:      aa.Type,
			Match:     aa.Match,
			Approvers: aa.Approvers,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.CreateAutoApprover(ctx, autoApprover); err != nil {
			handleError(w, err)
			return
		}
	}

	for i, na := range state.NodeAttrs {
		nodeAttr := &domain.NodeAttr{
			ID:        generateID(),
			StackID:   stackID,
			Order:     i,
			Target:    na.Target,
			Attr:      na.Attr,
			App:       na.App,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if na.Order != 0 {
			nodeAttr.Order = na.Order
		}
		if err := tx.CreateNodeAttr(ctx, nodeAttr); err != nil {
			handleError(w, err)
			return
		}
	}

	for _, p := range state.Postures {
		posture := &domain.Posture{
			ID:        generateID(),
			StackID:   stackID,
			Name:      p.Name,
			Rules:     p.Rules,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.CreatePosture(ctx, posture); err != nil {
			handleError(w, err)
			return
		}
	}

	for _, is := range state.IPSets {
		ipset := &domain.IPSet{
			ID:        generateID(),
			StackID:   stackID,
			Name:      is.Name,
			Addresses: is.Addresses,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.CreateIPSet(ctx, ipset); err != nil {
			handleError(w, err)
			return
		}
	}

	for i, t := range state.Tests {
		test := &domain.ACLTest{
			ID:        generateID(),
			StackID:   stackID,
			Order:     i,
			Source:    t.Source,
			Accept:    t.Accept,
			Deny:      t.Deny,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if t.Order != 0 {
			test.Order = t.Order
		}
		if err := tx.CreateACLTest(ctx, test); err != nil {
			handleError(w, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusOK, map[string]string{"status": "ok"}, h.syncService)
}
