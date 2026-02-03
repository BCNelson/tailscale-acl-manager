package handler

import (
	"net/http"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/go-chi/chi/v5"
)

// ACLTestHandler handles ACL test endpoints.
type ACLTestHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewACLTestHandler creates a new ACLTestHandler.
func NewACLTestHandler(store storage.Storage, syncService *service.SyncService) *ACLTestHandler {
	return &ACLTestHandler{store: store, syncService: syncService}
}

// Create creates a new ACL test.
func (h *ACLTestHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateACLTestRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Source == "" {
		respondError(w, http.StatusBadRequest, "src is required")
		return
	}

	now := time.Now()
	test := &domain.ACLTest{
		ID:        generateID(),
		StackID:   stackID,
		Order:     req.Order,
		Source:    req.Source,
		Accept:    req.Accept,
		Deny:      req.Deny,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateACLTest(r.Context(), test); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusCreated, test)
}

// List lists all ACL tests for a stack.
func (h *ACLTestHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	tests, err := h.store.ListACLTests(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, tests)
}

// Get gets an ACL test by ID.
func (h *ACLTestHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	test, err := h.store.GetACLTest(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, test)
}

// Update updates an ACL test.
func (h *ACLTestHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	var req domain.UpdateACLTestRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	test, err := h.store.GetACLTest(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if req.Order != nil {
		test.Order = *req.Order
	}
	if req.Source != nil {
		test.Source = *req.Source
	}
	if req.Accept != nil {
		test.Accept = req.Accept
	}
	if req.Deny != nil {
		test.Deny = req.Deny
	}

	if err := h.store.UpdateACLTest(r.Context(), test); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusOK, test)
}

// Delete deletes an ACL test.
func (h *ACLTestHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	if err := h.store.DeleteACLTest(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	w.WriteHeader(http.StatusNoContent)
}
