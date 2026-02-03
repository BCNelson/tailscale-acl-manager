package tailscale

import (
	"context"
	"encoding/json"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	tsclient "github.com/tailscale/tailscale-client-go/v2"
)

// PolicyClient defines the interface for interacting with Tailscale policies.
type PolicyClient interface {
	GetPolicy(ctx context.Context) (*domain.TailscalePolicy, string, error)
	SetPolicy(ctx context.Context, policy *domain.TailscalePolicy, etag string) (string, error)
	ValidatePolicy(ctx context.Context, policy *domain.TailscalePolicy) error
}

// Client wraps the Tailscale API client.
type Client struct {
	client  *tsclient.Client
	tailnet string
}

// Ensure Client implements PolicyClient.
var _ PolicyClient = (*Client)(nil)

// New creates a new Tailscale client.
func New(apiKey, tailnet string) (*Client, error) {
	client := &tsclient.Client{
		APIKey:  apiKey,
		Tailnet: tailnet,
	}
	return &Client{client: client, tailnet: tailnet}, nil
}

// GetPolicy gets the current ACL policy from Tailscale.
func (c *Client) GetPolicy(ctx context.Context) (*domain.TailscalePolicy, string, error) {
	acl, err := c.client.PolicyFile().Get(ctx)
	if err != nil {
		return nil, "", err
	}

	// Convert from Tailscale client types to our domain types
	var result domain.TailscalePolicy
	policyJSON, err := json.Marshal(acl)
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(policyJSON, &result); err != nil {
		return nil, "", err
	}

	return &result, acl.ETag, nil
}

// SetPolicy sets the ACL policy on Tailscale.
// The etag is used for optimistic locking - pass empty string to skip check.
func (c *Client) SetPolicy(ctx context.Context, policy *domain.TailscalePolicy, etag string) (string, error) {
	// Convert our domain types to Tailscale client types
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}

	var tsACL tsclient.ACL
	if err := json.Unmarshal(policyJSON, &tsACL); err != nil {
		return "", err
	}

	if err := c.client.PolicyFile().Set(ctx, tsACL, etag); err != nil {
		return "", err
	}

	// After successful set, get the new ETag
	newACL, err := c.client.PolicyFile().Get(ctx)
	if err != nil {
		// Set succeeded but couldn't get new ETag
		return "", nil
	}

	return newACL.ETag, nil
}

// ValidatePolicy validates a policy without setting it.
func (c *Client) ValidatePolicy(ctx context.Context, policy *domain.TailscalePolicy) error {
	// Convert our domain types to Tailscale client types
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	var tsACL tsclient.ACL
	if err := json.Unmarshal(policyJSON, &tsACL); err != nil {
		return err
	}

	return c.client.PolicyFile().Validate(ctx, tsACL)
}
