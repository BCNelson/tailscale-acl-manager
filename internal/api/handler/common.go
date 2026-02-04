package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/validation"
	"github.com/google/uuid"
)

// respondJSON writes a JSON response.
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// respondError writes a JSON error response using the new standardized format.
func respondError(w http.ResponseWriter, status int, message string) {
	code := httpStatusToErrorCode(status)
	respondStandardError(w, status, code, message, "", nil)
}

// respondStandardError writes a standardized JSON error response.
func respondStandardError(w http.ResponseWriter, status int, code, message, field string, details map[string]any) {
	respondJSON(w, status, &domain.StandardErrorResponse{
		Error: domain.StandardError{
			Code:    code,
			Message: message,
			Field:   field,
			Details: details,
		},
	})
}

// httpStatusToErrorCode converts HTTP status to error code.
func httpStatusToErrorCode(status int) string {
	switch status {
	case http.StatusNotFound:
		return domain.ErrCodeResourceNotFound
	case http.StatusConflict:
		return domain.ErrCodeResourceAlreadyExists
	case http.StatusBadRequest:
		return domain.ErrCodeInvalidInput
	case http.StatusUnauthorized:
		return domain.ErrCodeUnauthorized
	case http.StatusPreconditionFailed:
		return domain.ErrCodePreconditionFailed
	default:
		return domain.ErrCodeInternalError
	}
}

// handleError converts domain errors to HTTP errors.
func handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		respondStandardError(w, http.StatusNotFound, domain.ErrCodeResourceNotFound, "resource not found", "", nil)
	case errors.Is(err, domain.ErrAlreadyExists):
		respondStandardError(w, http.StatusConflict, domain.ErrCodeResourceAlreadyExists, "resource already exists", "", nil)
	case errors.Is(err, domain.ErrInvalidInput):
		respondStandardError(w, http.StatusBadRequest, domain.ErrCodeInvalidInput, "invalid input", "", nil)
	case errors.Is(err, domain.ErrUnauthorized):
		respondStandardError(w, http.StatusUnauthorized, domain.ErrCodeUnauthorized, "unauthorized", "", nil)
	case errors.Is(err, domain.ErrPreconditionFailed):
		respondStandardError(w, http.StatusPreconditionFailed, domain.ErrCodePreconditionFailed, "precondition failed", "", nil)
	case errors.Is(err, domain.ErrSyncInProgress):
		respondStandardError(w, http.StatusConflict, domain.ErrCodeSyncInProgress, "sync already in progress", "", nil)
	case errors.Is(err, domain.ErrSyncFailed):
		respondStandardError(w, http.StatusInternalServerError, domain.ErrCodeSyncFailed, "sync failed", "", nil)
	default:
		respondStandardError(w, http.StatusInternalServerError, domain.ErrCodeInternalError, "internal server error", "", nil)
	}
}

// decodeJSON decodes JSON from request body.
func decodeJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return domain.ErrInvalidInput
	}
	return nil
}

// generateID generates a new UUID.
func generateID() string {
	return uuid.New().String()
}

// generateAPIKey generates a new random API key.
func generateAPIKey() (key string, hash string, prefix string, err error) {
	// Generate 32 random bytes for the key
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", "", err
	}

	key = "acl_" + hex.EncodeToString(bytes)
	hash = hashKey(key)
	prefix = key[:12] // "acl_" + first 8 chars of hex

	return key, hash, prefix, nil
}

// hashKey creates a SHA-256 hash of the API key.
func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// respondValidationError writes a JSON validation error response using standardized format.
func respondValidationError(w http.ResponseWriter, field, value, message string) {
	respondStandardError(w, http.StatusBadRequest, domain.ErrCodeValidationError, message, field, map[string]any{
		"value": value,
	})
}

// respondValidationErrors writes a JSON response for multiple validation errors using standardized format.
func respondValidationErrors(w http.ResponseWriter, errs validation.ValidationErrors) {
	// Convert validation errors to details map
	errList := make([]map[string]any, 0, len(errs))
	for _, e := range errs {
		errList = append(errList, map[string]any{
			"field":   e.Field,
			"value":   e.Value,
			"message": e.Message,
		})
	}
	respondStandardError(w, http.StatusBadRequest, domain.ErrCodeValidationError, "validation failed", "", map[string]any{
		"errors": errList,
	})
}

// shouldWaitForSync checks if the request has ?sync=true query parameter.
func shouldWaitForSync(r *http.Request) bool {
	return r.URL.Query().Get("sync") == "true"
}

// isDryRun checks if the request has ?dryRun=true query parameter.
func isDryRun(r *http.Request) bool {
	return r.URL.Query().Get("dryRun") == "true"
}

// respondDryRun writes a dry run response.
func respondDryRun(w http.ResponseWriter, preview any) {
	respondJSON(w, http.StatusOK, &domain.DryRunResponse{
		Preview: preview,
		DryRun:  true,
		Validation: struct {
			Valid bool `json:"valid"`
		}{Valid: true},
	})
}
