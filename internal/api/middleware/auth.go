package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
)

type contextKey string

const APIKeyContextKey contextKey = "api_key"

// Auth creates authentication middleware.
func Auth(store storage.Storage, bootstrapKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the API key from the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"code":401,"message":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"code":401,"message":"invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			apiKey := strings.TrimPrefix(authHeader, "Bearer ")
			if apiKey == "" {
				http.Error(w, `{"code":401,"message":"empty API key"}`, http.StatusUnauthorized)
				return
			}

			ctx := r.Context()

			// Check if we have any API keys in the database
			keyCount, err := store.CountAPIKeys(ctx)
			if err != nil {
				http.Error(w, `{"code":500,"message":"internal server error"}`, http.StatusInternalServerError)
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
					http.Error(w, `{"code":401,"message":"invalid API key"}`, http.StatusUnauthorized)
					return
				}
				http.Error(w, `{"code":500,"message":"internal server error"}`, http.StatusInternalServerError)
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
