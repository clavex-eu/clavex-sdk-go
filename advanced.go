package clavex

import (
	"context"
	"fmt"
	"time"
)

// ── Device trust ──────────────────────────────────────────────────────────────

// DeviceTrustService manages trusted devices for zero-trust session binding.
//
//	devices, err := client.DeviceTrust.List(ctx, orgID, userID)
type DeviceTrustService struct{ c *Client }

// List returns all trusted devices for a user.
func (s *DeviceTrustService) List(ctx context.Context, orgID, userID string) ([]TrustedDevice, error) {
	var out []TrustedDevice
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/trusted-devices", userID)), &out)
}

// Revoke removes a specific trusted device.
func (s *DeviceTrustService) Revoke(ctx context.Context, orgID, userID, deviceID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/trusted-devices/%s", userID, deviceID)))
}

// RevokeAll removes all trusted devices for a user.
func (s *DeviceTrustService) RevokeAll(ctx context.Context, orgID, userID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/trusted-devices", userID)))
}

// TrustedDevice is a device the user has registered as trusted.
type TrustedDevice struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	OrgID        string     `json:"org_id"`
	Name         string     `json:"name,omitempty"`
	UserAgent    string     `json:"user_agent,omitempty"`
	IPAddress    string     `json:"ip_address,omitempty"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	RegisteredAt time.Time  `json:"registered_at"`
}

// ── Cross-org token exchange ──────────────────────────────────────────────────

// CrossOrgTrustService manages RFC 8693 token exchange trust relationships
// between organisations. This allows users authenticated in org A to obtain
// tokens valid in org B without re-authenticating.
//
//	trust, err := client.CrossOrgTrust.Create(ctx, orgID, clavex.CreateCrossOrgTrustParams{
//	    TrustedOrgSlug: "partner-corp",
//	    AllowedScopes:  []string{"openid", "profile"},
//	})
type CrossOrgTrustService struct{ c *Client }

// CreateCrossOrgTrustParams defines the fields for a cross-org trust.
type CreateCrossOrgTrustParams struct {
	// TrustedOrgSlug is the slug of the org whose tokens will be accepted.
	TrustedOrgSlug string   `json:"trusted_org_slug"`
	// AllowedScopes limits the scopes that can be exchanged. Empty = all.
	AllowedScopes  []string `json:"allowed_scopes,omitempty"`
}

// Create establishes a new cross-org trust relationship.
func (s *CrossOrgTrustService) Create(ctx context.Context, orgID string, p CreateCrossOrgTrustParams) (*CrossOrgTrust, error) {
	var out CrossOrgTrust
	return &out, s.c.post(ctx, orgPath(orgID, "/cross-org-trusts"), p, &out)
}

// List returns all cross-org trust relationships for orgID (outbound).
func (s *CrossOrgTrustService) List(ctx context.Context, orgID string) ([]CrossOrgTrust, error) {
	var out []CrossOrgTrust
	return out, s.c.get(ctx, orgPath(orgID, "/cross-org-trusts"), &out)
}

// ListInbound returns trusts where other orgs trust orgID.
func (s *CrossOrgTrustService) ListInbound(ctx context.Context, orgID string) ([]CrossOrgTrust, error) {
	var out []CrossOrgTrust
	return out, s.c.get(ctx, orgPath(orgID, "/cross-org-trusts/inbound"), &out)
}

// Revoke removes a cross-org trust relationship.
func (s *CrossOrgTrustService) Revoke(ctx context.Context, orgID, trustID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/cross-org-trusts/%s", trustID)))
}

// CrossOrgTrust represents a token-exchange trust relationship.
type CrossOrgTrust struct {
	ID             string    `json:"id"`
	OrgID          string    `json:"org_id"`
	TrustedOrgSlug string    `json:"trusted_org_slug"`
	TrustedOrgID   string    `json:"trusted_org_id"`
	AllowedScopes  []string  `json:"allowed_scopes,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// ── Admin API keys ────────────────────────────────────────────────────────────

// APIKeyService manages superadmin API keys.
// API keys can be used instead of JWT bearer tokens for machine-to-machine
// integrations (CI/CD, IaC, provisioning tools).
//
//	key, err := client.APIKeys.Create(ctx, clavex.CreateAPIKeyParams{Name: "terraform"})
//	// key.Secret is only available at creation time — store it securely.
type APIKeyService struct{ c *Client }

// CreateAPIKeyParams defines the fields for a new API key.
type CreateAPIKeyParams struct {
	// Name is a human-readable label for the key (e.g. "terraform", "ci-pipeline").
	Name string `json:"name"`
	// ExpiresIn is the lifetime in seconds. 0 = no expiry.
	ExpiresIn int `json:"expires_in,omitempty"`
}

// CreateAPIKeyResult holds the newly created API key.
// The Secret field is only present at creation time and will never be
// returned again — store it in a secrets manager immediately.
type CreateAPIKeyResult struct {
	APIKey APIKey `json:"api_key"`
	// Secret is the plaintext key value. Only returned at creation.
	Secret string `json:"secret"`
}

// Create generates a new API key.
// Requires superadmin privileges.
func (s *APIKeyService) Create(ctx context.Context, p CreateAPIKeyParams) (*CreateAPIKeyResult, error) {
	var out CreateAPIKeyResult
	return &out, s.c.post(ctx, "/api/v1/superadmin/api-keys", p, &out)
}

// List returns all API keys.
// Requires superadmin privileges.
func (s *APIKeyService) List(ctx context.Context) ([]APIKey, error) {
	var out []APIKey
	return out, s.c.get(ctx, "/api/v1/superadmin/api-keys", &out)
}

// Revoke permanently invalidates an API key.
// Requires superadmin privileges.
func (s *APIKeyService) Revoke(ctx context.Context, keyID string) error {
	return s.c.delete(ctx, fmt.Sprintf("/api/v1/superadmin/api-keys/%s", keyID))
}

// APIKey is an admin API key record (without the secret).
type APIKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"` // e.g. "cvx_sk_..." for display
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
