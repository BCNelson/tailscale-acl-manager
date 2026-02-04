package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider wraps the OIDC provider and OAuth2 config.
type OIDCProvider struct {
	provider       *oidc.Provider
	oauth2Config   *oauth2.Config
	verifier       *oidc.IDTokenVerifier
	allowedDomains []string
}

// OIDCClaims represents the claims from an ID token.
type OIDCClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// NewOIDCProvider creates a new OIDC provider with discovery.
func NewOIDCProvider(ctx context.Context, issuerURL, clientID, clientSecret, redirectURL string, scopes, allowedDomains []string) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &OIDCProvider{
		provider:       provider,
		oauth2Config:   oauth2Config,
		verifier:       verifier,
		allowedDomains: allowedDomains,
	}, nil
}

// AuthCodeURL generates an authorization URL with state and nonce.
func (p *OIDCProvider) AuthCodeURL(state, nonce string) string {
	return p.oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
	)
}

// ExchangeResult contains the result of an authorization code exchange.
type ExchangeResult struct {
	Claims       *OIDCClaims
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

// Exchange exchanges an authorization code for tokens and validates the ID token.
func (p *OIDCProvider) Exchange(ctx context.Context, code, nonce string) (*ExchangeResult, error) {
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Verify nonce
	if idToken.Nonce != nonce {
		return nil, fmt.Errorf("nonce mismatch")
	}

	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &ExchangeResult{
		Claims:       &claims,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}, nil
}

// ValidateClaims checks if the claims meet requirements (e.g., domain restriction).
func (p *OIDCProvider) ValidateClaims(claims *OIDCClaims) error {
	if claims.Email == "" {
		return fmt.Errorf("email claim is required")
	}

	// Check domain restriction if configured
	if len(p.allowedDomains) > 0 {
		emailParts := strings.Split(claims.Email, "@")
		if len(emailParts) != 2 {
			return fmt.Errorf("invalid email format")
		}
		domain := strings.ToLower(emailParts[1])

		allowed := false
		for _, d := range p.allowedDomains {
			if strings.ToLower(d) == domain {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("email domain %s is not allowed", domain)
		}
	}

	return nil
}

// GenerateSecureString generates a cryptographically secure random string.
func GenerateSecureString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
