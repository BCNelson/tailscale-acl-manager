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

// ACLHandler handles ACL rule endpoints.
type ACLHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewACLHandler creates a new ACLHandler.
func NewACLHandler(store storage.Storage, syncService *service.SyncService) *ACLHandler {
	return &ACLHandler{store: store, syncService: syncService}
}

// Create creates a new ACL rule.
func (h *ACLHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateACLRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Action == "" {
		req.Action = "accept"
	}

	if len(req.Sources) == 0 || len(req.Destinations) == 0 {
		respondError(w, http.StatusBadRequest, "src and dst are required")
		return
	}

	// Validate sources and destinations
	var errs validation.ValidationErrors
	for i, src := range req.Sources {
		if err := validation.ValidateACLSource(src); err != nil {
			errs.Add(fmt.Sprintf("sources[%d]", i), src, err.Error())
		}
	}
	for i, dst := range req.Destinations {
		if err := validation.ValidateACLDestination(dst); err != nil {
			errs.Add(fmt.Sprintf("destinations[%d]", i), dst, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	now := time.Now()
	rule := &domain.ACLRule{
		ID:           generateID(),
		StackID:      stackID,
		Order:        req.Order,
		Action:       req.Action,
		Protocol:     req.Protocol,
		Sources:      req.Sources,
		Destinations: req.Destinations,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.store.CreateACLRule(r.Context(), rule); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusCreated, rule, h.syncService)
}

// List lists all ACL rules for a stack.
func (h *ACLHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	rules, err := h.store.ListACLRules(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, rules)
}

// Get gets an ACL rule by ID.
func (h *ACLHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	rule, err := h.store.GetACLRule(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, rule)
}

// Update updates an ACL rule.
func (h *ACLHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	var req domain.UpdateACLRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	rule, err := h.store.GetACLRule(r.Context(), id)
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
	if req.Protocol != nil {
		rule.Protocol = *req.Protocol
	}
	// Validate sources and destinations if provided
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
			if err := validation.ValidateACLDestination(dst); err != nil {
				errs.Add(fmt.Sprintf("destinations[%d]", i), dst, err.Error())
			}
		}
		rule.Destinations = req.Destinations
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	if err := h.store.UpdateACLRule(r.Context(), rule); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusOK, rule, h.syncService)
}

// Delete deletes an ACL rule.
func (h *ACLHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	if err := h.store.DeleteACLRule(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}
