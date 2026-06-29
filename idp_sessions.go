package clavex

import (
	"context"
	"fmt"
)

// IDPService manages identity providers (OIDC/SAML) within an organisation.
type IDPService struct{ c *Client }

// CreateIDPParams defines the fields for creating an identity provider.
type CreateIDPParams struct {
	Name              string            `json:"name"`
	Type              string            `json:"type"` // "oidc" | "saml" | "google" | "github" | ...
	Enabled           *bool             `json:"enabled,omitempty"`
	Config            map[string]string `json:"config,omitempty"`
	AllowJIT          bool              `json:"allow_jit,omitempty"`
	RolesClaim        string            `json:"roles_claim,omitempty"`
	RoleClaimMappings map[string]string `json:"role_claim_mappings,omitempty"`
}

// Create adds an identity provider to orgID.
func (s *IDPService) Create(ctx context.Context, orgID string, p CreateIDPParams) (*IdentityProvider, error) {
	var out IdentityProvider
	return &out, s.c.post(ctx, orgPath(orgID, "/identity-providers"), p, &out)
}

// List returns all identity providers in orgID.
func (s *IDPService) List(ctx context.Context, orgID string) ([]IdentityProvider, error) {
	var out []IdentityProvider
	return out, s.c.get(ctx, orgPath(orgID, "/identity-providers"), &out)
}

// Get retrieves a single identity provider.
func (s *IDPService) Get(ctx context.Context, orgID, idpID string) (*IdentityProvider, error) {
	var out IdentityProvider
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/identity-providers/%s", idpID)), &out)
}

// Update modifies an identity provider.
func (s *IDPService) Update(ctx context.Context, orgID, idpID string, p CreateIDPParams) (*IdentityProvider, error) {
	var out IdentityProvider
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/identity-providers/%s", idpID)), p, &out)
}

// Delete removes an identity provider.
func (s *IDPService) Delete(ctx context.Context, orgID, idpID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/identity-providers/%s", idpID)))
}

// SessionService manages active user sessions.
type SessionService struct{ c *Client }

// ListByOrg returns all active sessions in an organisation.
func (s *SessionService) ListByOrg(ctx context.Context, orgID string) ([]ActiveSession, error) {
	var out []ActiveSession
	return out, s.c.get(ctx, orgPath(orgID, "/sessions"), &out)
}

// Revoke terminates a specific session.
func (s *SessionService) Revoke(ctx context.Context, orgID, sessionID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/sessions/%s", sessionID)))
}

// ListByUser returns active sessions for a specific user.
func (s *SessionService) ListByUser(ctx context.Context, orgID, userID string) ([]ActiveSession, error) {
	var out []ActiveSession
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/sessions", userID)), &out)
}

// RevokeAllByUser terminates every session for the given user.
func (s *SessionService) RevokeAllByUser(ctx context.Context, orgID, userID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/sessions", userID)))
}
