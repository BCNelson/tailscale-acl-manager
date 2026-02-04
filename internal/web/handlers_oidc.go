package web

import (
	"log"
	"net/http"
	"net/url"

	"github.com/bcnelson/tailscale-acl-manager/internal/auth"
)

// handleOIDCLogin initiates the OIDC login flow.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled || s.oidcProvider == nil {
		http.Error(w, "OIDC authentication is not enabled", http.StatusNotFound)
		return
	}

	// Generate state and nonce
	stateData, err := s.stateStore.Generate(w)
	if err != nil {
		log.Printf("Failed to generate OIDC state: %v", err)
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Failed to initiate login"), http.StatusSeeOther)
		return
	}

	// Redirect to OIDC provider
	authURL := s.oidcProvider.AuthCodeURL(stateData.State, stateData.Nonce)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// handleOIDCCallback handles the OIDC callback after authentication.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled || s.oidcProvider == nil {
		http.Error(w, "OIDC authentication is not enabled", http.StatusNotFound)
		return
	}

	ctx := r.Context()

	// Check for error from provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		if errDesc == "" {
			errDesc = errParam
		}
		log.Printf("OIDC provider returned error: %s - %s", errParam, errDesc)
		http.Redirect(w, r, "/login?error="+url.QueryEscape(errDesc), http.StatusSeeOther)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("No authorization code received"), http.StatusSeeOther)
		return
	}

	// Validate state
	state := r.URL.Query().Get("state")
	stateData, err := s.stateStore.Validate(r, state)
	if err != nil {
		log.Printf("OIDC state validation failed: %v", err)
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Invalid state parameter"), http.StatusSeeOther)
		return
	}

	// Clear state cookie
	s.stateStore.Clear(w)

	// Exchange code for tokens
	result, err := s.oidcProvider.Exchange(ctx, code, stateData.Nonce)
	if err != nil {
		log.Printf("OIDC token exchange failed: %v", err)
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Failed to complete authentication"), http.StatusSeeOther)
		return
	}

	// Validate claims (domain restriction, etc.)
	if err := s.oidcProvider.ValidateClaims(result.Claims); err != nil {
		log.Printf("OIDC claims validation failed: %v", err)
		http.Redirect(w, r, "/login?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	// Create session
	session := &auth.OIDCSession{
		Subject:      result.Claims.Subject,
		Email:        result.Claims.Email,
		Name:         result.Claims.Name,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenExpiry:  result.Expiry,
	}

	if err := s.sessionManager.Create(w, session); err != nil {
		log.Printf("Failed to create OIDC session: %v", err)
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Failed to create session"), http.StatusSeeOther)
		return
	}

	// Redirect to dashboard
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
