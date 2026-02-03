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

// respondError writes a JSON error response.
func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, &domain.APIError{
		Code:    status,
		Message: message,
	})
}

// handleError converts domain errors to HTTP errors.
func handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		respondError(w, http.StatusNotFound, "not found")
	case errors.Is(err, domain.ErrAlreadyExists):
		respondError(w, http.StatusConflict, "already exists")
	case errors.Is(err, domain.ErrInvalidInput):
		respondError(w, http.StatusBadRequest, "invalid input")
	case errors.Is(err, domain.ErrUnauthorized):
		respondError(w, http.StatusUnauthorized, "unauthorized")
	default:
		respondError(w, http.StatusInternalServerError, "internal server error")
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

// respondValidationError writes a JSON validation error response.
func respondValidationError(w http.ResponseWriter, field, value, message string) {
	respondJSON(w, http.StatusBadRequest, &validation.ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	})
}

// respondValidationErrors writes a JSON response for multiple validation errors.
func respondValidationErrors(w http.ResponseWriter, errs validation.ValidationErrors) {
	respondJSON(w, http.StatusBadRequest, map[string]any{
		"errors": errs,
	})
}
