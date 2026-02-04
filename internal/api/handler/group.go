package handler

import (
	"net/http"
	"net/url"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/bcnelson/tailscale-acl-manager/internal/validation"
	"github.com/go-chi/chi/v5"
)

// GroupHandler handles group endpoints.
type GroupHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewGroupHandler creates a new GroupHandler.
func NewGroupHandler(store storage.Storage, syncService *service.SyncService) *GroupHandler {
	return &GroupHandler{store: store, syncService: syncService}
}

// Create creates a new group.
func (h *GroupHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	// Verify stack exists
	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateGroupRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Validate group name format
	if err := validation.ValidateGroupName(req.Name); err != nil {
		respondValidationError(w, "name", req.Name, err.Error())
		return
	}

	// Validate members
	var errs validation.ValidationErrors
	for i, member := range req.Members {
		if err := validation.ValidateGroupMember(member); err != nil {
			errs.Add("members["+string(rune('0'+i))+"]", member, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	now := time.Now()
	group := &domain.Group{
		ID:        generateID(),
		StackID:   stackID,
		Name:      req.Name,
		Members:   req.Members,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Handle dry run mode
	if isDryRun(r) {
		respondDryRun(w, group)
		return
	}

	if err := h.store.CreateGroup(r.Context(), group); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusCreated, group, h.syncService)
}

// List lists all groups for a stack.
func (h *GroupHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	groups, err := h.store.ListGroups(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, groups)
}

// Get gets a group by name.
func (h *GroupHandler) Get(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	group, err := h.store.GetGroup(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	SetGroupETag(w, group)
	respondJSON(w, http.StatusOK, group)
}

// GetByID gets a group by UUID.
func (h *GroupHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	group, err := h.store.GetGroupByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	// Verify the group belongs to the requested stack
	if group.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	SetGroupETag(w, group)
	respondJSON(w, http.StatusOK, group)
}

// Update updates a group by name.
func (h *GroupHandler) Update(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	group, err := h.store.GetGroup(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	h.updateGroup(w, r, group)
}

// UpdateByID updates a group by UUID.
func (h *GroupHandler) UpdateByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	group, err := h.store.GetGroupByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	// Verify the group belongs to the requested stack
	if group.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	h.updateGroup(w, r, group)
}

// updateGroup is a helper that performs the actual update logic.
func (h *GroupHandler) updateGroup(w http.ResponseWriter, r *http.Request, group *domain.Group) {
	// Check If-Match header for optimistic concurrency (optional)
	if !CheckGroupIfMatch(r, group) {
		RespondPreconditionFailed(w, "group", group.ID, group.UpdatedAt)
		return
	}

	var req domain.UpdateGroupRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate members
	var errs validation.ValidationErrors
	for i, member := range req.Members {
		if err := validation.ValidateGroupMember(member); err != nil {
			errs.Add("members["+string(rune('0'+i))+"]", member, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	group.Members = req.Members

	// Handle dry run mode
	if isDryRun(r) {
		respondDryRun(w, group)
		return
	}

	if err := h.store.UpdateGroup(r.Context(), group); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusOK, group, h.syncService)
}

// Delete deletes a group by name.
func (h *GroupHandler) Delete(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	if err := h.store.DeleteGroup(r.Context(), stackID, name); err != nil {
		handleError(w, err)
		return
	}

	h.respondAfterDelete(w, r)
}

// DeleteByID deletes a group by UUID.
func (h *GroupHandler) DeleteByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	// First verify the group belongs to the requested stack
	group, err := h.store.GetGroupByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}
	if group.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	if err := h.store.DeleteGroupByID(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	h.respondAfterDelete(w, r)
}

// respondAfterDelete handles the response after a delete operation, including sync mode.
func (h *GroupHandler) respondAfterDelete(w http.ResponseWriter, r *http.Request) {
	respondDelete(w, r, h.syncService)
}
