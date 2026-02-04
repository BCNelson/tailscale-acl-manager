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

// NodeAttrHandler handles node attribute endpoints.
type NodeAttrHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewNodeAttrHandler creates a new NodeAttrHandler.
func NewNodeAttrHandler(store storage.Storage, syncService *service.SyncService) *NodeAttrHandler {
	return &NodeAttrHandler{store: store, syncService: syncService}
}

// Create creates a new node attribute.
func (h *NodeAttrHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateNodeAttrRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Target) == 0 {
		respondError(w, http.StatusBadRequest, "target is required")
		return
	}

	// Validate targets
	var errs validation.ValidationErrors
	for i, target := range req.Target {
		if err := validation.ValidateNodeAttrTarget(target); err != nil {
			errs.Add(fmt.Sprintf("target[%d]", i), target, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	now := time.Now()
	attr := &domain.NodeAttr{
		ID:        generateID(),
		StackID:   stackID,
		Order:     req.Order,
		Target:    req.Target,
		Attr:      req.Attr,
		App:       req.App,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateNodeAttr(r.Context(), attr); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusCreated, attr, h.syncService)
}

// List lists all node attributes for a stack.
func (h *NodeAttrHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	attrs, err := h.store.ListNodeAttrs(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, attrs)
}

// Get gets a node attribute by ID.
func (h *NodeAttrHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	attr, err := h.store.GetNodeAttr(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, attr)
}

// Update updates a node attribute.
func (h *NodeAttrHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	var req domain.UpdateNodeAttrRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	attr, err := h.store.GetNodeAttr(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if req.Order != nil {
		attr.Order = *req.Order
	}
	if req.Target != nil {
		// Validate targets
		var errs validation.ValidationErrors
		for i, target := range req.Target {
			if err := validation.ValidateNodeAttrTarget(target); err != nil {
				errs.Add(fmt.Sprintf("target[%d]", i), target, err.Error())
			}
		}
		if errs.HasErrors() {
			respondValidationErrors(w, errs)
			return
		}
		attr.Target = req.Target
	}
	if req.Attr != nil {
		attr.Attr = req.Attr
	}
	if req.App != nil {
		attr.App = req.App
	}

	if err := h.store.UpdateNodeAttr(r.Context(), attr); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusOK, attr, h.syncService)
}

// Delete deletes a node attribute.
func (h *NodeAttrHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	if err := h.store.DeleteNodeAttr(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}
