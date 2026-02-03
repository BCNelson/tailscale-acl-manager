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

// AutoApproverHandler handles auto approver endpoints.
type AutoApproverHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewAutoApproverHandler creates a new AutoApproverHandler.
func NewAutoApproverHandler(store storage.Storage, syncService *service.SyncService) *AutoApproverHandler {
	return &AutoApproverHandler{store: store, syncService: syncService}
}

// Create creates a new auto approver.
func (h *AutoApproverHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateAutoApproverRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Type == "" || req.Match == "" {
		respondError(w, http.StatusBadRequest, "type and match are required")
		return
	}

	if req.Type != "routes" && req.Type != "exitNode" {
		respondError(w, http.StatusBadRequest, "type must be 'routes' or 'exitNode'")
		return
	}

	// Validate match format based on type
	if err := validation.ValidateAutoApproverMatch(req.Type, req.Match); err != nil {
		respondValidationError(w, "match", req.Match, err.Error())
		return
	}

	// Validate approvers
	var errs validation.ValidationErrors
	for i, approver := range req.Approvers {
		if err := validation.ValidateAutoApprover(approver); err != nil {
			errs.Add(fmt.Sprintf("approvers[%d]", i), approver, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	now := time.Now()
	aa := &domain.AutoApprover{
		ID:        generateID(),
		StackID:   stackID,
		Type:      req.Type,
		Match:     req.Match,
		Approvers: req.Approvers,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateAutoApprover(r.Context(), aa); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusCreated, aa)
}

// List lists all auto approvers for a stack.
func (h *AutoApproverHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	aas, err := h.store.ListAutoApprovers(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, aas)
}

// Get gets an auto approver by ID.
func (h *AutoApproverHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	aa, err := h.store.GetAutoApprover(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, aa)
}

// Update updates an auto approver.
func (h *AutoApproverHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	var req domain.UpdateAutoApproverRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	aa, err := h.store.GetAutoApprover(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	// Validate approvers
	var errs validation.ValidationErrors
	for i, approver := range req.Approvers {
		if err := validation.ValidateAutoApprover(approver); err != nil {
			errs.Add(fmt.Sprintf("approvers[%d]", i), approver, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	aa.Approvers = req.Approvers

	if err := h.store.UpdateAutoApprover(r.Context(), aa); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusOK, aa)
}

// Delete deletes an auto approver.
func (h *AutoApproverHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	if err := h.store.DeleteAutoApprover(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	w.WriteHeader(http.StatusNoContent)
}
