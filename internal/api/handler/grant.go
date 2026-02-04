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

// GrantHandler handles grant endpoints.
type GrantHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewGrantHandler creates a new GrantHandler.
func NewGrantHandler(store storage.Storage, syncService *service.SyncService) *GrantHandler {
	return &GrantHandler{store: store, syncService: syncService}
}

// Create creates a new grant.
func (h *GrantHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateGrantRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
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
		if err := validation.ValidateACLSource(dst); err != nil { // Grant destinations use same format as sources
			errs.Add(fmt.Sprintf("destinations[%d]", i), dst, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	now := time.Now()
	grant := &domain.Grant{
		ID:           generateID(),
		StackID:      stackID,
		Order:        req.Order,
		Sources:      req.Sources,
		Destinations: req.Destinations,
		IP:           req.IP,
		App:          req.App,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.store.CreateGrant(r.Context(), grant); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusCreated, grant, h.syncService)
}

// List lists all grants for a stack.
func (h *GrantHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	grants, err := h.store.ListGrants(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, grants)
}

// Get gets a grant by ID.
func (h *GrantHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	grant, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, grant)
}

// Update updates a grant.
func (h *GrantHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	var req domain.UpdateGrantRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	grant, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if req.Order != nil {
		grant.Order = *req.Order
	}
	// Validate sources and destinations if provided
	var errs validation.ValidationErrors
	if req.Sources != nil {
		for i, src := range req.Sources {
			if err := validation.ValidateACLSource(src); err != nil {
				errs.Add(fmt.Sprintf("sources[%d]", i), src, err.Error())
			}
		}
		grant.Sources = req.Sources
	}
	if req.Destinations != nil {
		for i, dst := range req.Destinations {
			if err := validation.ValidateACLSource(dst); err != nil {
				errs.Add(fmt.Sprintf("destinations[%d]", i), dst, err.Error())
			}
		}
		grant.Destinations = req.Destinations
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}
	if req.IP != nil {
		grant.IP = req.IP
	}
	if req.App != nil {
		grant.App = req.App
	}

	if err := h.store.UpdateGrant(r.Context(), grant); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusOK, grant, h.syncService)
}

// Delete deletes a grant.
func (h *GrantHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	if err := h.store.DeleteGrant(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}
