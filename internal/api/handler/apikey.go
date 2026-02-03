package handler

import (
	"net/http"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/go-chi/chi/v5"
)

// APIKeyHandler handles API key endpoints.
type APIKeyHandler struct {
	store storage.Storage
}

// NewAPIKeyHandler creates a new APIKeyHandler.
func NewAPIKeyHandler(store storage.Storage) *APIKeyHandler {
	return &APIKeyHandler{store: store}
}

// Create creates a new API key.
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateAPIKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	key, hash, prefix, err := generateAPIKey()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}

	apiKey := &domain.APIKey{
		ID:        generateID(),
		Name:      req.Name,
		KeyHash:   hash,
		KeyPrefix: prefix,
		CreatedAt: time.Now(),
	}

	if err := h.store.CreateAPIKey(r.Context(), apiKey); err != nil {
		handleError(w, err)
		return
	}

	resp := &domain.CreateAPIKeyResponse{
		ID:        apiKey.ID,
		Name:      apiKey.Name,
		Key:       key, // Only returned on creation
		KeyPrefix: apiKey.KeyPrefix,
		CreatedAt: apiKey.CreatedAt,
	}

	respondJSON(w, http.StatusCreated, resp)
}

// List lists all API keys (without the actual key values).
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.ListAPIKeys(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, keys)
}

// Delete deletes an API key.
func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	if err := h.store.DeleteAPIKey(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
