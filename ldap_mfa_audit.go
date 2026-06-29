package clavex

import (
	"context"
	"fmt"
)

// LDAPService manages LDAP federation connections for an organisation.
type LDAPService struct{ c *Client }

// CreateLDAPParams defines the fields for an LDAP connection.
type CreateLDAPParams struct {
	Name            string `json:"name"`
	Vendor          string `json:"vendor,omitempty"` // "ad" | "openldap" | ...
	Host            string `json:"host"`
	Port            int    `json:"port,omitempty"`
	UseTLS          bool   `json:"use_tls,omitempty"`
	BindDN          string `json:"bind_dn"`
	BindPassword    string `json:"bind_password"`
	UsersDN         string `json:"users_dn"`
	UserObjectClass string `json:"user_object_class,omitempty"`
	UIDAttribute    string `json:"uid_attribute,omitempty"`
	EmailAttribute  string `json:"email_attribute,omitempty"`
	SyncEnabled     bool   `json:"sync_enabled,omitempty"`
}

// Create creates a new LDAP connection in orgID.
func (s *LDAPService) Create(ctx context.Context, orgID string, p CreateLDAPParams) (*LDAPConnection, error) {
	var out LDAPConnection
	return &out, s.c.post(ctx, orgPath(orgID, "/ldap"), p, &out)
}

// List returns all LDAP connections in orgID.
func (s *LDAPService) List(ctx context.Context, orgID string) ([]LDAPConnection, error) {
	var out []LDAPConnection
	return out, s.c.get(ctx, orgPath(orgID, "/ldap"), &out)
}

// Get retrieves a single LDAP connection.
func (s *LDAPService) Get(ctx context.Context, orgID, ldapID string) (*LDAPConnection, error) {
	var out LDAPConnection
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/ldap/%s", ldapID)), &out)
}

// Update modifies an LDAP connection.
func (s *LDAPService) Update(ctx context.Context, orgID, ldapID string, p CreateLDAPParams) (*LDAPConnection, error) {
	var out LDAPConnection
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/ldap/%s", ldapID)), p, &out)
}

// Delete removes an LDAP connection.
func (s *LDAPService) Delete(ctx context.Context, orgID, ldapID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/ldap/%s", ldapID)))
}

// TestConnectionResult holds the result of an LDAP connectivity test.
type TestConnectionResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// TestConnection verifies that the server can reach the LDAP host.
func (s *LDAPService) TestConnection(ctx context.Context, orgID, ldapID string) (*TestConnectionResult, error) {
	var out TestConnectionResult
	return &out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/ldap/%s/test", ldapID)), nil, &out)
}

// Sync triggers an immediate LDAP user sync.
func (s *LDAPService) Sync(ctx context.Context, orgID, ldapID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/ldap/%s/sync", ldapID)), nil, nil)
}

// MFAService manages MFA credentials (admin view).
type MFAService struct{ c *Client }

// List returns all MFA credentials enrolled by a user.
func (s *MFAService) List(ctx context.Context, orgID, userID string) ([]MFACredential, error) {
	var out []MFACredential
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/mfa", userID)), &out)
}

// Delete removes a specific MFA credential.
func (s *MFAService) Delete(ctx context.Context, orgID, userID, credID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/mfa/%s", userID, credID)))
}

// AuditService provides read access to the audit log.
type AuditService struct{ c *Client }

// AuditListParams carries optional filter parameters for audit queries.
type AuditListParams struct {
	UserID    string `url:"user_id,omitempty"`
	EventType string `url:"event_type,omitempty"`
	Limit     int    `url:"limit,omitempty"`
	Offset    int    `url:"offset,omitempty"`
}

// List returns audit log entries for orgID.
// Pass a zero-value AuditListParams{} to retrieve all entries.
func (s *AuditService) List(ctx context.Context, orgID string) ([]AuditLogEntry, error) {
	var out []AuditLogEntry
	return out, s.c.get(ctx, orgPath(orgID, "/audit"), &out)
}
