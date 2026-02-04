package domain

import "errors"

// Common errors used throughout the application.
var (
	ErrNotFound            = errors.New("not found")
	ErrAlreadyExists       = errors.New("already exists")
	ErrInvalidInput        = errors.New("invalid input")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrConflict            = errors.New("conflict")
	ErrSyncInProgress      = errors.New("sync already in progress")
	ErrSyncFailed          = errors.New("sync failed")
	ErrNoAPIKeys           = errors.New("no API keys configured")
	ErrInvalidAPIKey       = errors.New("invalid API key")
	ErrBootstrapDisabled   = errors.New("bootstrap key disabled - API keys exist")
	ErrPreconditionFailed  = errors.New("precondition failed")
)

// Error codes for standardized API error responses.
const (
	ErrCodeResourceNotFound     = "RESOURCE_NOT_FOUND"
	ErrCodeResourceAlreadyExists = "RESOURCE_ALREADY_EXISTS"
	ErrCodeInvalidInput         = "INVALID_INPUT"
	ErrCodeUnauthorized         = "UNAUTHORIZED"
	ErrCodeValidationError      = "VALIDATION_ERROR"
	ErrCodePreconditionFailed   = "PRECONDITION_FAILED"
	ErrCodeSyncInProgress       = "SYNC_IN_PROGRESS"
	ErrCodeSyncFailed           = "SYNC_FAILED"
	ErrCodeInternalError        = "INTERNAL_ERROR"
)

// StandardError represents a standardized error response from the API.
type StandardError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Field   string         `json:"field,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// StandardErrorResponse wraps a StandardError for JSON responses.
type StandardErrorResponse struct {
	Error StandardError `json:"error"`
}

// APIError represents an error response from the API (deprecated, use StandardError).
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return e.Message
}
