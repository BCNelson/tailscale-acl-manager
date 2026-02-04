package handler

import (
	"net/http"
	"net/url"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/go-chi/chi/v5"
)

// PostureHandler handles posture endpoints.
type PostureHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewPostureHandler creates a new PostureHandler.
func NewPostureHandler(store storage.Storage, syncService *service.SyncService) *PostureHandler {
	return &PostureHandler{store: store, syncService: syncService}
}

// Create creates a new posture.
func (h *PostureHandler) Create(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	if _, err := h.store.GetStack(r.Context(), stackID); err != nil {
		handleError(w, err)
		return
	}

	var req domain.CreatePostureRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	now := time.Now()
	posture := &domain.Posture{
		ID:        generateID(),
		StackID:   stackID,
		Name:      req.Name,
		Rules:     req.Rules,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreatePosture(r.Context(), posture); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusCreated, posture, h.syncService)
}

// List lists all postures for a stack.
func (h *PostureHandler) List(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	if stackID == "" {
		respondError(w, http.StatusBadRequest, "stack_id is required")
		return
	}

	postures, err := h.store.ListPostures(r.Context(), stackID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, postures)
}

// Get gets a posture by name.
func (h *PostureHandler) Get(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	posture, err := h.store.GetPosture(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, posture)
}

// GetByID gets a posture by UUID.
func (h *PostureHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	posture, err := h.store.GetPostureByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if posture.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	respondJSON(w, http.StatusOK, posture)
}

// Update updates a posture by name.
func (h *PostureHandler) Update(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	posture, err := h.store.GetPosture(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	h.updatePosture(w, r, posture)
}

// UpdateByID updates a posture by UUID.
func (h *PostureHandler) UpdateByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	posture, err := h.store.GetPostureByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if posture.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	h.updatePosture(w, r, posture)
}

// updatePosture is a helper that performs the actual update logic.
func (h *PostureHandler) updatePosture(w http.ResponseWriter, r *http.Request, posture *domain.Posture) {
	var req domain.UpdatePostureRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	posture.Rules = req.Rules

	if err := h.store.UpdatePosture(r.Context(), posture); err != nil {
		handleError(w, err)
		return
	}

	respondMutation(w, r, http.StatusOK, posture, h.syncService)
}

// Delete deletes a posture by name.
func (h *PostureHandler) Delete(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	if err := h.store.DeletePosture(r.Context(), stackID, name); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}

// DeleteByID deletes a posture by UUID.
func (h *PostureHandler) DeleteByID(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	id := chi.URLParam(r, "id")
	if stackID == "" || id == "" {
		respondError(w, http.StatusBadRequest, "stack_id and id are required")
		return
	}

	posture, err := h.store.GetPostureByID(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}
	if posture.StackID != stackID {
		handleError(w, domain.ErrNotFound)
		return
	}

	if err := h.store.DeletePostureByID(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	respondDelete(w, r, h.syncService)
}
