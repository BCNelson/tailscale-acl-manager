package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

const (
	sessionCookieName = "acl_session"
	sessionDuration   = 24 * time.Hour
)

type contextKey string

const sessionContextKey contextKey = "session"

// Session represents an authenticated user session.
type Session struct {
	APIKey      *domain.APIKey
	OIDCEmail   string // Set when authenticated via OIDC
	OIDCName    string // Set when authenticated via OIDC
	OIDCSubject string // Set when authenticated via OIDC
	IsOIDC      bool   // True if authenticated via OIDC
}

// sessionAuth is middleware that validates session cookies.
// It checks OIDC session first (if enabled), then falls back to API key.
func (s *Server) sessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Try OIDC session first (if enabled)
		if s.oidcEnabled && s.sessionManager != nil {
			oidcSession, err := s.sessionManager.Get(r)
			if err == nil {
				// Valid OIDC session
				session := &Session{
					OIDCEmail:   oidcSession.Email,
					OIDCName:    oidcSession.Name,
					OIDCSubject: oidcSession.Subject,
					IsOIDC:      true,
				}
				ctx = context.WithValue(ctx, sessionContextKey, session)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Fall back to API key session
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate the API key from the cookie
		apiKey := cookie.Value
		if apiKey == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check if we have any API keys in the database
		keyCount, err := s.store.CountAPIKeys(ctx)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		var storedKey *domain.APIKey

		// If no keys exist and bootstrap key is set, allow bootstrap key
		if keyCount == 0 && s.bootstrapKey != "" {
			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(s.bootstrapKey)) == 1 {
				storedKey = &domain.APIKey{
					ID:   "bootstrap",
					Name: "Bootstrap Key",
				}
			}
		}

		// If not bootstrap, validate against stored keys
		if storedKey == nil {
			keyHash := hashAPIKey(apiKey)
			storedKey, err = s.store.GetAPIKeyByHash(ctx, keyHash)
			if err != nil {
				// Invalid or expired session
				clearSessionCookie(w)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Update last used timestamp (fire and forget)
			go func() {
				_ = s.store.UpdateAPIKeyLastUsed(context.Background(), storedKey.ID)
			}()
		}

		// Store session in context
		session := &Session{APIKey: storedKey}
		ctx = context.WithValue(ctx, sessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// setSessionCookie sets the session cookie.
func setSessionCookie(w http.ResponseWriter, apiKey string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    apiKey,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   false, // Set to true in production with HTTPS
	})
}

// clearSessionCookie clears the session cookie.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// hashAPIKey creates a SHA-256 hash of the API key.
func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}
