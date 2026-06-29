package clavex

import (
	"context"
	"fmt"
)

// ClientService manages OIDC/OAuth2 clients within an organisation.
type ClientService struct{ c *Client }

// CreateClientParams defines the fields for creating a client.
type CreateClientParams struct {
	Name                string   `json:"name"`
	ClientID            string   `json:"client_id,omitempty"`
	RedirectURIs        []string `json:"redirect_uris"`
	PostLogoutRedirects []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes          []string `json:"grant_types,omitempty"`
	ResponseTypes       []string `json:"response_types,omitempty"`
	IsPublic            bool     `json:"is_public,omitempty"`
	IsActive            *bool    `json:"is_active,omitempty"`
}

// UpdateClientParams are the mutable fields of a client.
type UpdateClientParams struct {
	Name                *string  `json:"name,omitempty"`
	RedirectURIs        []string `json:"redirect_uris,omitempty"`
	PostLogoutRedirects []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes          []string `json:"grant_types,omitempty"`
	ResponseTypes       []string `json:"response_types,omitempty"`
	IsActive            *bool    `json:"is_active,omitempty"`
}

// Create creates a new client in orgID.
func (s *ClientService) Create(ctx context.Context, orgID string, p CreateClientParams) (*CreateClientResponse, error) {
	var out CreateClientResponse
	return &out, s.c.post(ctx, orgPath(orgID, "/clients"), p, &out)
}

// List returns all clients in orgID.
func (s *ClientService) List(ctx context.Context, orgID string) ([]OIDCClient, error) {
	var out []OIDCClient
	return out, s.c.get(ctx, orgPath(orgID, "/clients"), &out)
}

// Get retrieves a single client.
func (s *ClientService) Get(ctx context.Context, orgID, clientID string) (*OIDCClient, error) {
	var out OIDCClient
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s", clientID)), &out)
}

// Update modifies a client.
func (s *ClientService) Update(ctx context.Context, orgID, clientID string, p UpdateClientParams) (*OIDCClient, error) {
	var out OIDCClient
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s", clientID)), p, &out)
}

// Delete removes a client.
func (s *ClientService) Delete(ctx context.Context, orgID, clientID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s", clientID)))
}

// RotateSecret generates a new client secret and returns the updated client.
func (s *ClientService) RotateSecret(ctx context.Context, orgID, clientID string) (*CreateClientResponse, error) {
	var out CreateClientResponse
	return &out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s/rotate-secret", clientID)), nil, &out)
}

// ClientScopeService manages custom OIDC scopes within an organisation.
type ClientScopeService struct{ c *Client }

// CreateClientScopeParams defines the fields for a scope.
type CreateClientScopeParams struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Protocol    string `json:"protocol,omitempty"` // "openid-connect" | "saml"
}

// Create creates a new client scope.
func (s *ClientScopeService) Create(ctx context.Context, orgID string, p CreateClientScopeParams) (*ClientScope, error) {
	var out ClientScope
	return &out, s.c.post(ctx, orgPath(orgID, "/client-scopes"), p, &out)
}

// List returns all client scopes in orgID.
func (s *ClientScopeService) List(ctx context.Context, orgID string) ([]ClientScope, error) {
	var out []ClientScope
	return out, s.c.get(ctx, orgPath(orgID, "/client-scopes"), &out)
}

// Update modifies a client scope.
func (s *ClientScopeService) Update(ctx context.Context, orgID, scopeID string, p CreateClientScopeParams) (*ClientScope, error) {
	var out ClientScope
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/client-scopes/%s", scopeID)), p, &out)
}

// Delete removes a client scope.
func (s *ClientScopeService) Delete(ctx context.Context, orgID, scopeID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/client-scopes/%s", scopeID)))
}

// ListByClient returns the scopes assigned to a specific client.
func (s *ClientScopeService) ListByClient(ctx context.Context, orgID, clientID string) ([]ClientScope, error) {
	var out []ClientScope
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s/scopes", clientID)), &out)
}

// AssignToClient attaches a scope to a client.
func (s *ClientScopeService) AssignToClient(ctx context.Context, orgID, clientID, scopeID string) error {
	return s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s/scopes/%s", clientID, scopeID)), nil, nil)
}

// UnassignFromClient detaches a scope from a client.
func (s *ClientScopeService) UnassignFromClient(ctx context.Context, orgID, clientID, scopeID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s/scopes/%s", clientID, scopeID)))
}

// ProtocolMapperService manages protocol mappers attached to a client.
type ProtocolMapperService struct{ c *Client }

// CreateProtocolMapperParams defines the fields for a protocol mapper.
type CreateProtocolMapperParams struct {
	Name       string            `json:"name"`
	Protocol   string            `json:"protocol"`    // "openid-connect" | "saml"
	MapperType string            `json:"mapper_type"` // e.g. "user-attribute"
	Config     map[string]string `json:"config,omitempty"`
}

// Create adds a protocol mapper to a client.
func (s *ProtocolMapperService) Create(ctx context.Context, orgID, clientID string, p CreateProtocolMapperParams) (*ProtocolMapper, error) {
	var out ProtocolMapper
	return &out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s/mappers", clientID)), p, &out)
}

// List returns all protocol mappers for a client.
func (s *ProtocolMapperService) List(ctx context.Context, orgID, clientID string) ([]ProtocolMapper, error) {
	var out []ProtocolMapper
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s/mappers", clientID)), &out)
}

// Update modifies a protocol mapper.
func (s *ProtocolMapperService) Update(ctx context.Context, orgID, clientID, mapperID string, p CreateProtocolMapperParams) (*ProtocolMapper, error) {
	var out ProtocolMapper
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s/mappers/%s", clientID, mapperID)), p, &out)
}

// Delete removes a protocol mapper.
func (s *ProtocolMapperService) Delete(ctx context.Context, orgID, clientID, mapperID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/clients/%s/mappers/%s", clientID, mapperID)))
}
