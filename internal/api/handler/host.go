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

// HostHandler handles host endpoints.
type HostHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewHostHandler creates a new HostHandler.
func NewHostHandler(store storage.Storage, syncService *service.SyncService) *HostHandler {
	return &HostHandler{store: store, syncService: syncService}
}

// Create creates a new host.
func (h *HostHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateHostRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.Address == "" {
		respondError(w, http.StatusBadRequest, "name and address are required")
		return
	}

	// Validate host name format
	if err := validation.ValidateHostName(req.Name); err != nil {
		respondValidationError(w, "name", req.Name, err.Error())
		return
	}

	// Validate address format
	if err := validation.ValidateHostAddress(req.Address); err != nil {
		respondValidationError(w, "address", req.Address, err.Error())
		return
	}

	now := time.Now()
	host := &domain.Host{
		ID:        generateID(),
		StackID:   stackID,
		Name:      req.Name,
		Address:   req.Address,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateHost(r.Context(), host); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusCreated, host, h.syncService)
}

// List lists all hosts for a stack.
func (h *HostHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	hosts, err := h.store.ListHosts(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, hosts)
}

// Get gets a host by name.
func (h *HostHandler) Get(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	host, err := h.store.GetHost(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, host)
}

// GetByID gets a host by UUID.
func (h *HostHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	host, err := h.store.GetHostByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if host.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	respondJSON(w, http.StatusOK, host)
}

// Update updates a host by name.
func (h *HostHandler) Update(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	host, err := h.store.GetHost(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	h.updateHost(w, r, host)
}

// UpdateByID updates a host by UUID.
func (h *HostHandler) UpdateByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	host, err := h.store.GetHostByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if host.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	h.updateHost(w, r, host)
}

// updateHost is a helper that performs the actual update logic.
func (h *HostHandler) updateHost(w http.ResponseWriter, r *http.Request, host *domain.Host) {
	var req domain.UpdateHostRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate address format
	if err := validation.ValidateHostAddress(req.Address); err != nil {
		respondValidationError(w, "address", req.Address, err.Error())
		return
	}

	host.Address = req.Address

	if err := h.store.UpdateHost(r.Context(), host); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusOK, host, h.syncService)
}

// Delete deletes a host by name.
func (h *HostHandler) Delete(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	if err := h.store.DeleteHost(r.Context(), stackID, name); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}

// DeleteByID deletes a host by UUID.
func (h *HostHandler) DeleteByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	host, err := h.store.GetHostByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}
	if host.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	if err := h.store.DeleteHostByID(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}
