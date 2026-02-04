package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/bcnelson/tailscale-acl-manager/internal/validation"
	"github.com/go-chi/chi/v5"
)

// SSHHandler handles SSH rule endpoints.
type SSHHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewSSHHandler creates a new SSHHandler.
func NewSSHHandler(store storage.Storage, syncService *service.SyncService) *SSHHandler {
	return &SSHHandler{store: store, syncService: syncService}
}

// Create creates a new SSH rule.
func (h *SSHHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateSSHRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Action == "" {
		respondError(w, http.StatusBadRequest, "action is required")
		return
	}

	// Validate sources, destinations, and users
	var errs validation.ValidationErrors
	for i, src := range req.Sources {
		if err := validation.ValidateACLSource(src); err != nil {
			errs.Add(fmt.Sprintf("sources[%d]", i), src, err.Error())
		}
	}
	for i, dst := range req.Destinations {
		if err := validation.ValidateACLSource(dst); err != nil { // SSH destinations use same format as sources
			errs.Add(fmt.Sprintf("destinations[%d]", i), dst, err.Error())
		}
	}
	for i, user := range req.Users {
		if err := validation.ValidateSSHUser(user); err != nil {
			errs.Add(fmt.Sprintf("users[%d]", i), user, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	now := time.Now()
	rule := &domain.SSHRule{
		ID:           generateID(),
		StackID:      stackID,
		Order:        req.Order,
		Action:       req.Action,
		Sources:      req.Sources,
		Destinations: req.Destinations,
		Users:        req.Users,
		CheckPeriod:  req.CheckPeriod,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.store.CreateSSHRule(r.Context(), rule); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusCreated, rule, h.syncService)
}

// List lists all SSH rules for a stack.
func (h *SSHHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	rules, err := h.store.ListSSHRules(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, rules)
}

// Get gets an SSH rule by ID.
func (h *SSHHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	rule, err := h.store.GetSSHRule(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, rule)
}

// Update updates an SSH rule.
func (h *SSHHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	var req domain.UpdateSSHRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	rule, err := h.store.GetSSHRule(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if req.Order != nil {
		rule.Order = *req.Order
	}
	if req.Action != nil {
		rule.Action = *req.Action
	}
	// Validate sources, destinations, and users if provided
	var errs validation.ValidationErrors
	if req.Sources != nil {
		for i, src := range req.Sources {
			if err := validation.ValidateACLSource(src); err != nil {
				errs.Add(fmt.Sprintf("sources[%d]", i), src, err.Error())
			}
		}
		rule.Sources = req.Sources
	}
	if req.Destinations != nil {
		for i, dst := range req.Destinations {
			if err := validation.ValidateACLSource(dst); err != nil {
				errs.Add(fmt.Sprintf("destinations[%d]", i), dst, err.Error())
			}
		}
		rule.Destinations = req.Destinations
	}
	if req.Users != nil {
		for i, user := range req.Users {
			if err := validation.ValidateSSHUser(user); err != nil {
				errs.Add(fmt.Sprintf("users[%d]", i), user, err.Error())
			}
		}
		rule.Users = req.Users
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}
	if req.CheckPeriod != nil {
		rule.CheckPeriod = *req.CheckPeriod
	}

	if err := h.store.UpdateSSHRule(r.Context(), rule); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusOK, rule, h.syncService)
}

// Delete deletes an SSH rule.
func (h *SSHHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	if err := h.store.DeleteSSHRule(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}
