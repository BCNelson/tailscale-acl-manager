package domain

import "errors"

// Common errors used throughout the application.
var (
	ErrNotFound          = errors.New("not found")
	ErrAlreadyExists     = errors.New("already exists")
	ErrInvalidInput      = errors.New("invalid input")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrConflict          = errors.New("conflict")
	ErrSyncInProgress    = errors.New("sync already in progress")
	ErrSyncFailed        = errors.New("sync failed")
	ErrNoAPIKeys         = errors.New("no API keys configured")
	ErrInvalidAPIKey     = errors.New("invalid API key")
	ErrBootstrapDisabled = errors.New("bootstrap key disabled - API keys exist")
)

// APIError represents an error response from the API.
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return e.Message
}
