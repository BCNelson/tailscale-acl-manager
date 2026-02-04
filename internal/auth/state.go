package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// StateCookieName is the name of the state cookie.
	StateCookieName = "acl_oidc_state"
	// StateCookieMaxAge is how long the state cookie is valid (5 minutes).
	StateCookieMaxAge = 5 * 60
)

// StateStore manages state and nonce for OIDC CSRF protection.
type StateStore struct {
	aead   cipher.AEAD
	secure bool
}

// StateData holds the state and nonce for an OIDC request.
type StateData struct {
	State     string    `json:"state"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewStateStore creates a new state store with encryption.
func NewStateStore(key []byte, secure bool) (*StateStore, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("state store key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &StateStore{
		aead:   aead,
		secure: secure,
	}, nil
}

// Generate creates a new state/nonce pair and stores it in an encrypted cookie.
func (ss *StateStore) Generate(w http.ResponseWriter) (*StateData, error) {
	state, err := GenerateSecureString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	nonce, err := GenerateSecureString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	data := &StateData{
		State:     state,
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(StateCookieMaxAge * time.Second),
	}

	// Serialize and encrypt
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state: %w", err)
	}

	nonceBytes := make([]byte, ss.aead.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := ss.aead.Seal(nonceBytes, nonceBytes, plaintext, nil)
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)

	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   StateCookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   ss.secure,
	})

	return data, nil
}

// Validate retrieves and validates the state from the cookie.
func (ss *StateStore) Validate(r *http.Request, state string) (*StateData, error) {
	cookie, err := r.Cookie(StateCookieName)
	if err != nil {
		return nil, fmt.Errorf("state cookie not found: %w", err)
	}

	// Decode from base64
	ciphertext, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode state: %w", err)
	}

	// Decrypt
	if len(ciphertext) < ss.aead.NonceSize() {
		return nil, fmt.Errorf("invalid state data")
	}

	nonce := ciphertext[:ss.aead.NonceSize()]
	ciphertext = ciphertext[ss.aead.NonceSize():]

	plaintext, err := ss.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt state: %w", err)
	}

	// Deserialize
	var data StateData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Check expiration
	if time.Now().After(data.ExpiresAt) {
		return nil, fmt.Errorf("state expired")
	}

	// Validate state matches (constant-time comparison)
	if !ConstantTimeCompare(data.State, state) {
		return nil, fmt.Errorf("state mismatch")
	}

	return &data, nil
}

// Clear clears the state cookie.
func (ss *StateStore) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   ss.secure,
	})
}
