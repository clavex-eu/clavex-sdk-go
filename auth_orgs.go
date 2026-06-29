package clavex

import (
	"context"
	"fmt"
)

// AuthService handles admin authentication.
type AuthService struct{ c *Client }

// LoginParams holds credentials for manual login.
type LoginParams struct {
	OrgSlug  string `json:"org_slug"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login authenticates an admin user and returns the JWT.
// When using WithCredentials, this is called automatically — you do not need
// to call it directly unless you want the raw response.
//
//	resp, err := client.Auth.Login(ctx, clavex.LoginParams{
//	    OrgSlug: "acme", Email: "admin@acme.com", Password: "secret",
//	})
func (s *AuthService) Login(ctx context.Context, p LoginParams) (*LoginResponse, error) {
	var out LoginResponse
	if err := s.c.post(ctx, "/api/v1/auth/login", p, &out); err != nil {
		return nil, err
	}
	// Also store in the client so subsequent calls use the fresh token.
	s.c.mu.Lock()
	s.c.token = out.Token
	s.c.mu.Unlock()
	return &out, nil
}

// SetToken overrides the current bearer token.
// Useful for externally managed token rotation.
func (s *AuthService) SetToken(token string) {
	s.c.mu.Lock()
	s.c.token = token
	s.c.mu.Unlock()
}

// OrgService manages organisations (superadmin operations).
type OrgService struct{ c *Client }

// CreateOrgParams defines the fields for creating an organisation.
type CreateOrgParams struct {
	Name    string  `json:"name"`
	Slug    string  `json:"slug"`
	LogoURL *string `json:"logo_url,omitempty"`
}

// Create creates a new organisation.
// Requires superadmin privileges.
func (s *OrgService) Create(ctx context.Context, p CreateOrgParams) (*Organization, error) {
	var out Organization
	return &out, s.c.post(ctx, "/api/v1/organizations", p, &out)
}

// List returns all organisations.
// Requires superadmin privileges.
func (s *OrgService) List(ctx context.Context) ([]Organization, error) {
	var out []Organization
	return out, s.c.get(ctx, "/api/v1/organizations", &out)
}

// Get retrieves an organisation by ID.
func (s *OrgService) Get(ctx context.Context, orgID string) (*Organization, error) {
	var out Organization
	return &out, s.c.get(ctx, fmt.Sprintf("/api/v1/organizations/%s", orgID), &out)
}

// UpdateOrgParams are the mutable fields of an Organisation.
type UpdateOrgParams struct {
	Name        *string `json:"name,omitempty"`
	LogoURL     *string `json:"logo_url,omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`
	MFARequired *bool   `json:"mfa_required,omitempty"`
}

// Update modifies an organisation.
func (s *OrgService) Update(ctx context.Context, orgID string, p UpdateOrgParams) (*Organization, error) {
	var out Organization
	return &out, s.c.patch(ctx, fmt.Sprintf("/api/v1/organizations/%s", orgID), p, &out)
}

// Delete permanently removes an organisation and all its data.
func (s *OrgService) Delete(ctx context.Context, orgID string) error {
	return s.c.delete(ctx, fmt.Sprintf("/api/v1/organizations/%s", orgID))
}
