package handler

import (
	"net/http"
	"strconv"

	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/go-chi/chi/v5"
)

// PolicyHandler handles policy endpoints.
type PolicyHandler struct {
	store       storage.Storage
	syncService *service.SyncService
}

// NewPolicyHandler creates a new PolicyHandler.
func NewPolicyHandler(store storage.Storage, syncService *service.SyncService) *PolicyHandler {
	return &PolicyHandler{store: store, syncService: syncService}
}

// Get returns the current merged policy.
func (h *PolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	policy, err := h.syncService.GetMergedPolicy(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, policy)
}

// Preview returns a preview of the merged policy without pushing.
func (h *PolicyHandler) Preview(w http.ResponseWriter, r *http.Request) {
	policy, err := h.syncService.GetMergedPolicy(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, policy)
}

// Sync forces a sync to Tailscale.
func (h *PolicyHandler) Sync(w http.ResponseWriter, r *http.Request) {
	resp, err := h.syncService.ForceSync(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// ListVersions lists policy versions.
func (h *PolicyHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	limit := 20
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	versions, err := h.store.ListPolicyVersions(r.Context(), limit, offset)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, versions)
}

// Rollback rolls back to a previous policy version.
func (h *PolicyHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	resp, err := h.syncService.Rollback(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}
