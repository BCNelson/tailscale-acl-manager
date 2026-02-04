package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
)

type contextKey string

const APIKeyContextKey contextKey = "api_key"

// respondAuthError writes a standardized auth error response.
func respondAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(&domain.StandardErrorResponse{
		Error: domain.StandardError{
			Code:    domain.ErrCodeUnauthorized,
			Message: message,
		},
	})
}

// respondInternalError writes a standardized internal error response.
func respondInternalError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(&domain.StandardErrorResponse{
		Error: domain.StandardError{
			Code:    domain.ErrCodeInternalError,
			Message: "internal server error",
		},
	})
}

// Auth creates authentication middleware.
func Auth(store storage.Storage, bootstrapKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the API key from the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondAuthError(w, "missing authorization header")
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				respondAuthError(w, "invalid authorization header format")
				return
			}

			apiKey := strings.TrimPrefix(authHeader, "Bearer ")
			if apiKey == "" {
				respondAuthError(w, "empty API key")
				return
			}

			ctx := r.Context()

			// Check if we have any API keys in the database
			keyCount, err := store.CountAPIKeys(ctx)
			if err != nil {
				respondInternalError(w)
				return
			}

			// If no keys exist and bootstrap key is set, allow bootstrap key
			if keyCount == 0 && bootstrapKey != "" {
				if subtle.ConstantTimeCompare([]byte(apiKey), []byte(bootstrapKey)) == 1 {
					// Bootstrap key is valid, allow request
					ctx = context.WithValue(ctx, APIKeyContextKey, &domain.APIKey{
						ID:   "bootstrap",
						Name: "Bootstrap Key",
					})
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Hash the provided key and look it up
			keyHash := hashAPIKey(apiKey)
			storedKey, err := store.GetAPIKeyByHash(ctx, keyHash)
			if err != nil {
				if err == domain.ErrNotFound {
					respondAuthError(w, "invalid API key")
					return
				}
				respondInternalError(w)
				return
			}

			// Update last used timestamp (fire and forget)
			go func() {
				_ = store.UpdateAPIKeyLastUsed(context.Background(), storedKey.ID)
			}()

			// Store the API key in context
			ctx = context.WithValue(ctx, APIKeyContextKey, storedKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// hashAPIKey creates a SHA-256 hash of the API key.
// We use SHA-256 for fast lookups since API keys are already high-entropy random strings.
func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// GetAPIKeyFromContext retrieves the API key from the request context.
func GetAPIKeyFromContext(ctx context.Context) *domain.APIKey {
	key, _ := ctx.Value(APIKeyContextKey).(*domain.APIKey)
	return key
}
