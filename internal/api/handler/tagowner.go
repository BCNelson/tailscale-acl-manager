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

// TagOwnerHandler handles tag owner endpoints.
type TagOwnerHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewTagOwnerHandler creates a new TagOwnerHandler.
func NewTagOwnerHandler(store storage.Storage, syncService *service.SyncService) *TagOwnerHandler {
	return &TagOwnerHandler{store: store, syncService: syncService}
}

// Create creates a new tag owner.
func (h *TagOwnerHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreateTagOwnerRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Tag == "" {
		respondError(w, http.StatusBadRequest, "tag is required")
		return
	}

	// Validate tag name format
	if err := validation.ValidateTagName(req.Tag); err != nil {
		respondValidationError(w, "tag", req.Tag, err.Error())
		return
	}

	// Validate owners
	var errs validation.ValidationErrors
	for i, owner := range req.Owners {
		if err := validation.ValidateTagOwner(owner); err != nil {
			errs.Add("owners["+string(rune('0'+i))+"]", owner, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	now := time.Now()
	tagOwner := &domain.TagOwner{
		ID:        generateID(),
		StackID:   stackID,
		Tag:       req.Tag,
		Owners:    req.Owners,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateTagOwner(r.Context(), tagOwner); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusCreated, tagOwner)
}

// List lists all tag owners for a stack.
func (h *TagOwnerHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	tagOwners, err := h.store.ListTagOwners(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, tagOwners)
}

// Get gets a tag owner by tag.
func (h *TagOwnerHandler) Get(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	tag, _ := url.PathUnescape(chi.URLParam(r, "tag"))
	if stackID == "" || tag == "" {
		respondError(w, http.StatusBadRequest, "stack_id and tag are required")
		return
	}

	tagOwner, err := h.store.GetTagOwner(r.Context(), stackID, tag)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, tagOwner)
}

// Update updates a tag owner.
func (h *TagOwnerHandler) Update(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	tag, _ := url.PathUnescape(chi.URLParam(r, "tag"))
	if stackID == "" || tag == "" {
		respondError(w, http.StatusBadRequest, "stack_id and tag are required")
		return
	}

	var req domain.UpdateTagOwnerRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	tagOwner, err := h.store.GetTagOwner(r.Context(), stackID, tag)
	if err != nil {
		handleError(w, err)
		return
	}

	// Validate owners
	var errs validation.ValidationErrors
	for i, owner := range req.Owners {
		if err := validation.ValidateTagOwner(owner); err != nil {
			errs.Add("owners["+string(rune('0'+i))+"]", owner, err.Error())
		}
	}
	if errs.HasErrors() {
		respondValidationErrors(w, errs)
		return
	}

	tagOwner.Owners = req.Owners

	if err := h.store.UpdateTagOwner(r.Context(), tagOwner); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusOK, tagOwner)
}

// Delete deletes a tag owner.
func (h *TagOwnerHandler) Delete(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	tag, _ := url.PathUnescape(chi.URLParam(r, "tag"))
	if stackID == "" || tag == "" {
		respondError(w, http.StatusBadRequest, "stack_id and tag are required")
		return
	}

	if err := h.store.DeleteTagOwner(r.Context(), stackID, tag); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	w.WriteHeader(http.StatusNoContent)
}
