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

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusCreated, posture)
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

// Update updates a posture.
func (h *PostureHandler) Update(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "stack_id")
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if stackID == "" || name == "" {
		respondError(w, http.StatusBadRequest, "stack_id and name are required")
		return
	}

	var req domain.UpdatePostureRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	posture, err := h.store.GetPosture(r.Context(), stackID, name)
	if err != nil {
		handleError(w, err)
		return
	}

	posture.Rules = req.Rules

	if err := h.store.UpdatePosture(r.Context(), posture); err != nil {
		handleError(w, err)
		return
	}

	h.syncService.TriggerSync()
	respondJSON(w, http.StatusOK, posture)
}

// Delete deletes a posture.
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

	h.syncService.TriggerSync()
	w.WriteHeader(http.StatusNoContent)
}
