package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/bcnelson/tailscale-acl-manager/internal/validation"
	"github.com/go-chi/chi/v5"
)

// IPSetHandler handles IP set endpoints.
type IPSetHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewIPSetHandler creates a new IPSetHandler.
func NewIPSetHandler(store storage.Storage, syncService *service.SyncService) *IPSetHandler {
	return &IPSetHandler{store: store, syncService: syncService}
}

// Create creates a new IP set.
func (h *IPSetHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateIPSetRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Validate IP set name format
	if err := validation.ValidateIPSetName(req.Name); err != nil {
		respondValidationError(w, "name", req.Name, err.Error())
		return
	}

	// Validate addresses
	var errs validation.ValidationErrors
	for i, addr := range req.Addresses {
		if err := validation.ValidateHostAddress(addr); err != nil {
			errs.Add(fmt.Sprintf("addresses[%d]", i), addr, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	now := time.Now()
	ipset := &domain.IPSet{
		ID:        generateID(),
		StackID:   stackID,
		Name:      req.Name,
		Addresses: req.Addresses,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateIPSet(r.Context(), ipset); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusCreated, ipset)
}

// List lists all IP sets for a stack.
func (h *IPSetHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	ipsets, err := h.store.ListIPSets(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, ipsets)
}

// Get gets an IP set by name.
func (h *IPSetHandler) Get(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	ipset, err := h.store.GetIPSet(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, ipset)
}

// Update updates an IP set.
func (h *IPSetHandler) Update(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	var req domain.UpdateIPSetRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ipset, err := h.store.GetIPSet(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	// Validate addresses
	var errs validation.ValidationErrors
	for i, addr := range req.Addresses {
		if err := validation.ValidateHostAddress(addr); err != nil {
			errs.Add(fmt.Sprintf("addresses[%d]", i), addr, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	ipset.Addresses = req.Addresses

	if err := h.store.UpdateIPSet(r.Context(), ipset); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusOK, ipset)
}

// Delete deletes an IP set.
func (h *IPSetHandler) Delete(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	if err := h.store.DeleteIPSet(r.Context(), stackID, name); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	w.WriteHeader(http.StatusNoContent)
}
