package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// OIDCSessionCookieName is the name of the OIDC session cookie.
	OIDCSessionCookieName = "acl_oidc_session"
)

// SessionManager handles encrypted session cookies.
type SessionManager struct {
	aead     cipher.AEAD
	duration time.Duration
	secure   bool // Use Secure flag on cookies (for HTTPS)
}

// OIDCSession represents the session data stored in the encrypted cookie.
type OIDCSession struct {
	Subject      string    `json:"sub"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenExpiry  time.Time `json:"token_expiry,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// NewSessionManager creates a new session manager with the given encryption key.
// The key must be exactly 32 bytes for AES-256.
func NewSessionManager(key []byte, duration time.Duration, secure bool) (*SessionManager, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("session key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &SessionManager{
		aead:     aead,
		duration: duration,
		secure:   secure,
	}, nil
}

// Create creates an encrypted session cookie.
func (sm *SessionManager) Create(w http.ResponseWriter, session *OIDCSession) error {
	session.CreatedAt = time.Now()
	session.ExpiresAt = time.Now().Add(sm.duration)

	// Serialize session to JSON
	plaintext, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Encrypt with AES-256-GCM
	nonce := make([]byte, sm.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := sm.aead.Seal(nonce, nonce, plaintext, nil)
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)

	http.SetCookie(w, &http.Cookie{
		Name:     OIDCSessionCookieName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   int(sm.duration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   sm.secure,
	})

	return nil
}

// Get retrieves and validates the session from the cookie.
func (sm *SessionManager) Get(r *http.Request) (*OIDCSession, error) {
	cookie, err := r.Cookie(OIDCSessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie not found: %w", err)
	}

	// Decode from base64
	ciphertext, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session: %w", err)
	}

	// Decrypt
	if len(ciphertext) < sm.aead.NonceSize() {
		return nil, fmt.Errorf("invalid session data")
	}

	nonce := ciphertext[:sm.aead.NonceSize()]
	ciphertext = ciphertext[sm.aead.NonceSize():]

	plaintext, err := sm.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session: %w", err)
	}

	// Deserialize
	var session OIDCSession
	if err := json.Unmarshal(plaintext, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}

// Clear clears the session cookie.
func (sm *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     OIDCSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   sm.secure,
	})
}

// NeedsRefresh checks if the access token is close to expiring.
func (sm *SessionManager) NeedsRefresh(session *OIDCSession) bool {
	if session.TokenExpiry.IsZero() {
		return false
	}
	// Refresh if token expires within 5 minutes
	return time.Until(session.TokenExpiry) < 5*time.Minute
}

// ConstantTimeCompare performs a constant-time comparison of two strings.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
